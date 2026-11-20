// SPEC.md held to the code it specifies (SMTP-M9-33). Each of E1 to E3 and Z1 to Z9 has its section,
// tests of its own and a mutated witness, and the argument's steps S1 to S7 and K1 to K4 have theirs; and
// the bytes M9's exit review would freeze reproduce from fixed connections in testdata/vectors: each part's
// statement as field elements (SPEC.md 5.1), its counts, C and its carries as on the wire, the templates the
// edge computes, and one key-part proof beside a test setup's verifying key. The connections prove under
// every production shape between them. SMTPPROOF_WRITE_VECTORS rewrites the expected values. A connection
// file that is missing is captured anew, so deleting one renews it, and every expected value with it.

package smtpproof

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
)

// Every check §22.10 reviews, in SPEC.md's order.
var testSpecChecks = []string{"E1", "E2", "E3", "Z1", "Z2", "Z3", "Z4", "Z5", "Z6", "Z7", "Z8", "Z9"}

// The steps of SPEC.md's argument (DESIGN-DETAILS 3.3): soundness in section 9, zero knowledge in 10.2.
var testSpecSteps = []string{"S1", "S2", "S3", "S4", "S5", "S6", "S7", "K1", "K2", "K3", "K4"}

func TestSpecNamesEveryCheck(t *testing.T) {
	spec, err := os.ReadFile("SPEC.md")
	if err != nil {
		t.Fatal(err)
	}
	table, err := os.ReadFile(filepath.Join("testdata", "mutations", "table.md"))
	if err != nil {
		t.Fatal(err)
	}
	// the mutations themselves, before the table of cells no witness can break
	mutations, _, _ := strings.Cut(string(table), "Cells no witness")
	paths, err := filepath.Glob("*_test.go")
	if err != nil {
		t.Fatal(err)
	}
	var sources []byte
	for _, path := range paths {
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		sources = append(sources, source...)
	}
	for _, check := range testSpecChecks {
		// its definition: section 6's E1 to E3 and section 7's Z1 to Z9 each open in bold
		if !bytes.Contains(spec, []byte("**"+check+", ")) {
			t.Errorf("%s: SPEC.md defines no such check", check)
		}
		// tests of its own, beside the mutation table's
		own := regexp.MustCompile(`func Test` + check + `[A-Z]\w*\(t \*testing\.T\)`)
		if len(own.FindAll(sources, -1)) == 0 {
			t.Errorf("%s: no test of its own", check)
		}
		if !bytes.Contains(sources, []byte("func TestMutatedWitness"+check+"(t *testing.T)")) {
			t.Errorf("%s: no TestMutatedWitness%s", check, check)
		}
		if !strings.Contains(mutations, "\n| "+check+" | ") {
			t.Errorf("%s: no mutation in testdata/mutations/table.md", check)
		}
	}
	for _, step := range testSpecSteps {
		// each step opens in bold where the argument makes it, and only there
		if count := bytes.Count(spec, []byte("**"+step+", ")); count != 1 {
			t.Errorf("%s: SPEC.md makes the step %d times", step, count)
		}
	}
	for _, named := range []string{"testdata/mutations/table.md", "testdata/vectors/statements.json", "testdata/vectors/commit.json", "TestSpecVectorsReproduce", "TestSpecVectorsCoverEveryShape", "TestSpecPi1ProofVectorVerifies", "TestSpecHeaderRecordsOutlastEveryLiteral"} {
		if !bytes.Contains(spec, []byte(named)) {
			t.Errorf("SPEC.md does not name %s", named)
		}
	}
}

// SPEC.md 9.5's S4 rests on every literal the header scan seeks being shorter than a header record that is
// not the block's last, so that a literal straddles one record boundary at most, and on the scan state's
// run counting each literal's octets below its 127, which stands for more.
func TestSpecHeaderRecordsOutlastEveryLiteral(t *testing.T) {
	proof := DefaultProofSettings()
	for _, literal := range scanLiterals {
		if proof.HeaderRecordMinByteCount <= len(literal.octets) {
			t.Errorf("%q is %d octets, not under HeaderRecordMinByteCount's %d", literal.octets, len(literal.octets), proof.HeaderRecordMinByteCount)
		}
		if scanRunMore <= len(literal.octets) {
			t.Errorf("%q is %d octets, past what the state's run counts", literal.octets, len(literal.octets))
		}
	}
}

// A fixed connection the vectors read.
type testVectorConnection struct {
	name string
	leg  int
	data bool
	// The envelope a command a group and a header block of two records, so that env parts follow one
	// another and a hdr part opens the msg part's carry: with these, every production shape proves in some
	// vector.
	groups bool
}

func testVectorConnections() []*testVectorConnection {
	legs := []string{"tls13-aes", "tls13-chacha", "tls12-aes"}
	var connections []*testVectorConnection
	for leg, name := range legs {
		connections = append(connections,
			&testVectorConnection{name: name + "-bdat", leg: leg},
			&testVectorConnection{name: name + "-data", leg: leg, data: true})
	}
	for leg, name := range legs {
		connections = append(connections, &testVectorConnection{name: name + "-groups-bdat", leg: leg, groups: true})
	}
	return connections
}

// The filler lines that bring testHeaderBlock past what any family's msg shape holds in its head, so that the
// header block takes two records in every family.
const testVectorHeaderFillerLines = 24

// A BDAT send whose envelope goes a command a group (DESIGN-DETAILS 3.2.4) and whose header block takes two
// records: part 2 opens MAIL over the EHLO reply, each env part after it covers the command before's reply
// and opens the next RCPT, the msg part covers the last RCPT's reply and opens BDAT's command and header
// record 1, and a hdr part opens record 2 and QUIT.
func testCaptureGroups(t *testing.T, legIndex int) *ExportedCapture {
	t.Helper()
	leg := testTlsLegs()[legIndex%len(testTlsLegs())]
	job := testMessageJob(testOrderedHeaderBlock(testVectorHeaderFillerLines)+testExportBody, false)
	job.EnvelopeGroupMaxCount = 1
	send := testRunSend(t, leg, testMxDefaults(), DefaultProverSettings(), job)
	testExpectOneTransaction(t, leg, send, job)
	testExpectHeaderRecords(t, leg.name, send.edge.parts, 2)
	fixture := &testGateFixture{leg: leg, preamble: newSessionPreamble(job.Preamble, DefaultProofSettings()), trace: send.edge.trace, parts: send.edge.parts}
	return exportCapture(t, fixture, job, send.backend)
}

// The connection, as captured once and kept in testdata/vectors.
func (self *testVectorConnection) capture(t *testing.T) *ExportedCapture {
	t.Helper()
	path := filepath.Join("testdata", "vectors", "connection-"+self.name+".json")
	encoded, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		var captured *ExportedCapture
		if self.groups {
			captured = testCaptureGroups(t, self.leg)
		} else {
			captured = ExportCapture(t, self.leg, self.data)
		}
		if encoded, err = json.MarshalIndent(captured, "", " "); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, encoded, 0o644); err != nil {
			t.Fatal(err)
		}
	} else if err != nil {
		t.Fatal(err)
	}
	capture := &ExportedCapture{}
	if err := json.Unmarshal(encoded, capture); err != nil {
		t.Fatal(err)
	}
	return capture
}

// Keeps each statement the gate builds, with the witness its part had.
type testRecordingVerifier struct {
	witness    *partWitness
	statements []*partStatement
	witnesses  []*partWitness
}

func (self *testRecordingVerifier) verifyPart(ctx context.Context, statement *partStatement, proof []byte) error {
	self.statements = append(self.statements, statement)
	self.witnesses = append(self.witnesses, self.witness)
	return nil
}

// Each part's statement as the edge builds it from a connection, with its witness.
func testReplayStatements(t *testing.T, capture *ExportedCapture) ([]*partStatement, []*partWitness) {
	t.Helper()
	preamble := newSessionPreamble(capture.Preamble, DefaultProofSettings())
	if err := checkSessionPreamble(preamble); err != nil {
		t.Fatal(err)
	}
	verifier := &testRecordingVerifier{}
	gate := newEdgeSession(defaultEdgeSettings(), preamble, capture.Preamble.MxHost, verifier)
	for i, event := range capture.Events {
		var err error
		switch {
		case event.Part != nil:
			witness := capture.Witnesses[i]
			verifier.witness = importedWitness(witness)
			_, err = gate.VerifyPart(context.Background(), event.Part)
		case event.Shts != nil:
			_, err = gate.DiscloseShts(event.Shts)
		case event.ClientRecord != nil:
			_, err = gate.ClientRecord(event.ClientRecord)
		default:
			err = gate.ServerRecord(event.ServerRecord)
		}
		if err != nil {
			t.Fatalf("event %d: %v", i, err)
		}
	}
	return verifier.statements, verifier.witnesses
}

// One part's frozen bytes.
type testStatementVector struct {
	Index uint32 `json:"index"`
	Mode  uint32 `json:"mode"`
	// The production shape it proves under, by its KeySet name.
	Shape        string `json:"shape"`
	PublicInputs int    `json:"public_inputs"`
	// SHA-256 over the public inputs in order, each as 32 octets big-endian.
	Sha256 string `json:"sha256"`
	// The replies its server records hold, and k as the statement holds it: 0 before the part that opens
	// header record 1 names it.
	ReplyCount        uint32 `json:"reply_count"`
	HeaderRecordCount uint32 `json:"header_record_count"`
	// C, the carry the part opens and the carry it publishes, each in hex as on the wire: x then y, 32
	// octets each, big-endian.
	KeyCommitment string `json:"key_commitment"`
	CarryIn       string `json:"carry_in,omitempty"`
	CarryOut      string `json:"carry_out,omitempty"`
	// The template of each command record the part opens, in order.
	Templates []string `json:"templates,omitempty"`
}

// A template as text: literal octets as they are, and a run of local or free positions as its class
// and length between angle brackets no literal holds, such as ⟨local×8⟩.
func testRenderTemplate(template []templateOctet) string {
	var rendered strings.Builder
	for i := 0; i < len(template); {
		j := i
		for j < len(template) && template[j].kind == template[i].kind {
			j += 1
		}
		switch template[i].kind {
		case templateLiteral:
			for _, position := range template[i:j] {
				rendered.WriteByte(position.literal)
			}
		case templateLocal:
			fmt.Fprintf(&rendered, "⟨local×%d⟩", j-i)
		default:
			fmt.Fprintf(&rendered, "⟨free×%d⟩", j-i)
		}
		i = j
	}
	return rendered.String()
}

// A statement's public inputs, as SPEC.md 5.1 orders them.
func testPublicInputs(t *testing.T, statement *partStatement) (*partShape, fr.Vector) {
	t.Helper()
	shape, err := partShapeFor(DefaultProofSettings(), statement)
	if err != nil {
		t.Fatal(err)
	}
	circuit, err := partAssignment(shape, statement)
	if err != nil {
		t.Fatal(err)
	}
	public, err := frontend.NewWitness(circuit, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		t.Fatal(err)
	}
	return shape, public.Vector().(fr.Vector)
}

func testStatementVectorOf(t *testing.T, statement *partStatement) *testStatementVector {
	t.Helper()
	shape, inputs := testPublicInputs(t, statement)
	hash := sha256.New()
	for _, element := range inputs {
		octets := element.Bytes()
		hash.Write(octets[:])
	}
	vector := &testStatementVector{
		Index:             statement.index,
		Mode:              statement.mode,
		Shape:             partShapeName(shape),
		PublicInputs:      len(inputs),
		Sha256:            hex.EncodeToString(hash.Sum(nil)),
		ReplyCount:        statement.replyCount,
		HeaderRecordCount: statement.headerRecordCount,
		KeyCommitment:     hex.EncodeToString(statement.keyCommitment),
		CarryIn:           hex.EncodeToString(statement.carryIn),
		CarryOut:          hex.EncodeToString(statement.carryOut),
	}
	roles, err := partRoles(statement)
	if err != nil {
		t.Fatal(err)
	}
	for i, role := range roles {
		if role == recordRoleHeaderBlock || role == recordRoleBody {
			continue
		}
		template, err := clientRecordTemplate(statement.session, role, statement.clientRecords[i])
		if err != nil {
			t.Fatal(err)
		}
		vector.Templates = append(vector.Templates, testRenderTemplate(template))
	}
	return vector
}

// Fails unless the gate gave a connection's parts the commitments SPEC.md section 5 says it supplies: every
// part the key part's C, and each scan part's carry in the carry the scan part before it published, or the
// start constant wherever a scan starts, before the body's first record and after the header block's last.
func testExpectSuppliedCommitments(t *testing.T, name string, statements []*partStatement) {
	t.Helper()
	carry := scanStartCarry()
	for _, statement := range statements {
		if !bytes.Equal(statement.keyCommitment, statements[0].keyCommitment) {
			t.Errorf("%s: part %d is verified against another C than the key part's", name, statement.index)
		}
		if statement.carryIn != nil && !bytes.Equal(statement.carryIn, carry) {
			t.Errorf("%s: part %d opens another carry than the gate kept", name, statement.index)
		}
		if statement.carryOut != nil {
			carry = statement.carryOut
		}
		roles, err := partRoles(statement)
		if err != nil {
			t.Fatalf("%s: part %d: %v", name, statement.index, err)
		}
		for i, role := range roles {
			if role == recordRoleHeaderBlock && headerOrdinal(statement, statement.clientRecords[i].seq) == int(statement.headerRecordCount) {
				carry = scanStartCarry()
			}
		}
	}
}

func TestSpecVectorsReproduce(t *testing.T) {
	computed := map[string][]*testStatementVector{}
	for _, connection := range testVectorConnections() {
		statements, witnesses := testReplayStatements(t, connection.capture(t))
		for i, statement := range statements {
			// the fixed connections are honest, so every part satisfies the relation: C opens to its keys
			// under rho, and each carry to its state under its blind
			if failures := relationCheckPart(statement, witnesses[i]); len(failures) != 0 {
				t.Errorf("%s: part %d: %v", connection.name, statement.index, failures)
			}
			computed[connection.name] = append(computed[connection.name], testStatementVectorOf(t, statement))
		}
		testExpectSuppliedCommitments(t, connection.name, statements)
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", " ")
	if err := encoder.Encode(computed); err != nil {
		t.Fatal(err)
	}
	encoded := buffer.Bytes()
	path := filepath.Join("testdata", "vectors", "statements.json")
	if os.Getenv("SMTPPROOF_WRITE_VECTORS") != "" {
		if err := os.WriteFile(path, encoded, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(written, encoded) {
		t.Errorf("%s differs from what the fixed connections give; set SMTPPROOF_WRITE_VECTORS to rewrite it", path)
	}
}

// The fixed connections prove under every production shape between them, and set every flag a shape reads
// (SPEC.md 5.1), so the bytes the exit review freezes reach each circuit and each rule's public switch.
func TestSpecVectorsCoverEveryShape(t *testing.T) {
	proof := DefaultProofSettings()
	proved := map[string]bool{}
	flags := map[string]bool{}
	for _, connection := range testVectorConnections() {
		statements, _ := testReplayStatements(t, connection.capture(t))
		for _, statement := range statements {
			shape, err := partShapeFor(proof, statement)
			if err != nil {
				t.Fatalf("%s: part %d: %v", connection.name, statement.index, err)
			}
			proved[partShapeName(shape)] = true
			if 0 < shape.serverBlocks {
				flags["EhloRule"] = flags["EhloRule"] || statement.ehloRule()
				flags["RequireChunking"] = flags["RequireChunking"] || statement.requireChunking()
				flags["Last354"] = flags["Last354"] || statement.last354()
				flags["Tls13"] = flags["Tls13"] || statement.session.version == tlsVersion13
				flags["Tls13 at 0"] = flags["Tls13 at 0"] || statement.session.version == tlsVersion12
				flags["ReplyCount past 1"] = flags["ReplyCount past 1"] || 1 < statement.replyCount
			}
		}
	}
	for _, shape := range partShapes(proof) {
		if !proved[partShapeName(shape)] {
			t.Errorf("no vector proves under %s", partShapeName(shape))
		}
	}
	for _, flag := range []string{"EhloRule", "RequireChunking", "Last354", "Tls13", "Tls13 at 0", "ReplyCount past 1"} {
		if !flags[flag] {
			t.Errorf("no vector sets %s", flag)
		}
	}
}

func TestSpecPi1ProofVectorVerifies(t *testing.T) {
	// a proof is randomized, so the vector is one proof kept, beside the verifying key it verifies under
	// and the statement it was made for
	connection := testVectorConnections()[2]
	statements, witnesses := testReplayStatements(t, connection.capture(t))
	statement, witness := statements[0], witnesses[0]
	keyPath := filepath.Join("testdata", "vectors", "pi1-"+strings.TrimSuffix(connection.name, "-bdat")+".vk")
	proofPath := strings.TrimSuffix(keyPath, ".vk") + ".proof"
	if os.Getenv("SMTPPROOF_WRITE_VECTORS") != "" {
		testNeedCircuits(t)
		keys := testRealEhloKeys(t)
		backend := newGroth16Backend(DefaultProofSettings())
		backend.addKeys(keys)
		proof, err := backend.provePart(context.Background(), statement, witness)
		if err != nil {
			t.Fatal(err)
		}
		var key bytes.Buffer
		if _, err := keys.verifyingKey.WriteTo(&key); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyPath, key.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(proofPath, proof, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	encodedKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	verifyingKey := groth16.NewVerifyingKey(ecc.BN254)
	if _, err := verifyingKey.ReadFrom(bytes.NewReader(encodedKey)); err != nil {
		t.Fatal(err)
	}
	encodedProof, err := os.ReadFile(proofPath)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := decodeProof(encodedProof)
	if err != nil {
		t.Fatal(err)
	}
	shape, inputs := testPublicInputs(t, statement)
	if *shape != *partShapes(DefaultProofSettings())[1] {
		t.Fatalf("pi1 proves under %s", partShapeName(shape))
	}
	circuit, err := partAssignment(shape, statement)
	if err != nil {
		t.Fatal(err)
	}
	public, err := frontend.NewWitness(circuit, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		t.Fatal(err)
	}
	if err := groth16.Verify(proof, verifyingKey, public); err != nil {
		t.Fatalf("the kept proof does not verify: %v", err)
	}
	// and nothing but its statement: C's x, the first ciphertext octet, then the last public input. In
	// order: the three hashes, C, then the first pool block's counter and octets
	vector := public.Vector().(fr.Vector)
	for _, position := range []int{3 * 8 * tlsSecretBytes, 3*8*tlsSecretBytes + 3, len(inputs) - 1} {
		original := vector[position]
		var one fr.Element
		one.SetOne()
		vector[position].Add(&vector[position], &one)
		if err := groth16.Verify(proof, verifyingKey, public); err == nil {
			t.Errorf("public input %d moved: verified", position)
		}
		vector[position] = original
	}
}
