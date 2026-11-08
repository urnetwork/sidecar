// The Groth16 backend over pi1 at its real size, and what pi3's proving costs a prover host in memory.
// gnark's verifier takes the statement as field elements in the shape's order (SPEC.md 5.1), so a
// proof must bind every one of them: each public input one bit off must fail.

package smtpproof

import (
	"bufio"
	"context"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
)

// pi1's keys under ChaCha20, from a test-only setup at the shape's real size, shared by the tests
// that prove with them: the setup is the slow step.
var (
	testRealEhloLock sync.Mutex
	testRealEhlo     *shapeKeys
)

func testRealEhloKeys(t *testing.T) *shapeKeys {
	t.Helper()
	testRealEhloLock.Lock()
	defer testRealEhloLock.Unlock()
	if testRealEhlo == nil {
		testRealEhlo = testSetup(t, partShapes()[1])
	}
	return testRealEhlo
}

func TestGroth16RefusesEachPublicInputOneBitOff(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("runs a real setup")
	}
	keys := testRealEhloKeys(t)
	backend := newGroth16Backend()
	backend.addKeys(keys)
	capture := testBdatCapture(t, testTlsLegs()[1])
	statement, witness := capture.part(t, 1)
	encoded, err := backend.provePart(context.Background(), statement, witness)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := decodeProof(encoded)
	if err != nil {
		t.Fatal(err)
	}
	circuit, err := partAssignment(keys.shape, statement)
	if err != nil {
		t.Fatal(err)
	}
	public, err := frontend.NewWitness(circuit, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		t.Fatal(err)
	}
	if err := groth16.Verify(proof, keys.verifyingKey, public); err != nil {
		t.Fatalf("an honest proof did not verify: %v", err)
	}
	// the witness's own vector, so each change reaches what Verify reads
	vector := public.Vector().(fr.Vector)
	if len(vector) != keys.compiled.GetNbPublicVariables()-1 {
		t.Fatalf("%d public inputs for %d public variables", len(vector), keys.compiled.GetNbPublicVariables())
	}
	for i := range vector {
		original := vector[i]
		var value big.Int
		vector[i].BigInt(&value)
		value.SetBit(&value, 0, value.Bit(0)^1)
		vector[i].SetBigInt(&value)
		if err := groth16.Verify(proof, keys.verifyingKey, public); err == nil {
			t.Errorf("public input %d one bit off: verified", i)
		}
		vector[i] = original
	}
	if err := groth16.Verify(proof, keys.verifyingKey, public); err != nil {
		t.Errorf("the restored statement: %v", err)
	}
	t.Logf("%d public inputs, each refused one bit off", len(vector))
}

// The public positions a test shape leaves to Z1, which it leaves out: 1.3's three hashes first, or
// 1.2's handshake inputs and SF last.
func testZ1InputPositions(shape *partShape, publics int) (int, int) {
	if !shape.withoutKeySchedule {
		return 0, 0
	}
	if shape.version == tlsVersion13 {
		return 0, 3 * 8 * tlsSecretBytes
	}
	inputs := 8 * (2*tlsRandomBytes + 2*tlsSecretBytes + 2*sha256BlockBytes)
	inputs += 6 + 1 + 1 + shapeBlockBytes12
	return publics - inputs, publics
}

// A 1.2 shape's blocks are AES's.
const shapeBlockBytes12 = 16

// The test shapes the mutation table's circuits solve a DATA send's later parts on, which compile once
// for both tests.
func testLaterPartShapes(t *testing.T, leg *testTlsLeg) []*partShape {
	t.Helper()
	settings := DefaultProverSettings()
	settings.ForceData = true
	settings.DataPartBytes = 12
	capture := testCapture(t, leg, testMxDefaults(), settings, testJob("one line\r\nanother line\r\nand a third\r\n", "bob", "carol"))
	var shapes []*partShape
	for _, statement := range capture.statements {
		if statement.index < 4 {
			continue
		}
		shape, err := testShapeFitting(statement, 0, 8)
		if err != nil {
			t.Fatal(err)
		}
		shapes = append(shapes, shape)
	}
	return shapes
}

func TestEveryPublicWireIsConstrained(t *testing.T) {
	t.Parallel()
	// Groth16's verifier weighs each public input by its own element of the verifying key, which is the
	// identity for a wire no constraint reads, so a proof would verify whatever value the edge gave it.
	// Every kind of shape on every leg, with and without the local table, server blocks and body
	// blocks, each a shape other tests compile too; the test shapes leave Z1 out, so their handshake
	// inputs are the two pi1 shapes' to show
	shapes := []*partShape{
		partShapes()[1],
		test12Shape(),
	}
	for _, leg := range testTlsLegs() {
		suite := leg.suites[0]
		bodyBlocks := 6
		if suite == tlsSuiteChacha20Poly1305Sha256 {
			bodyBlocks = 2
		}
		shapes = append(shapes,
			testQuickShape(suite, false),
			testQuickShape(suite, true),
			testQuickEnvelopeShape(suite),
			testQuickMessageShape(suite, 0),
			testQuickMessageShape(suite, bodyBlocks),
		)
		shapes = append(shapes, testLaterPartShapes(t, leg)...)
	}
	// a later part over a late ticket, as part_data_test.go's
	shapes = append(shapes,
		&partShape{kind: partKindBody, version: tlsVersion13, suite: tlsSuiteAes128GcmSha256, clientBlocks: 2, serverBlocks: 7, bodyBlocks: 2, withoutKeySchedule: true},
		&partShape{kind: partKindBody, version: tlsVersion13, suite: tlsSuiteChacha20Poly1305Sha256, clientBlocks: 2, serverBlocks: 2, bodyBlocks: 1, withoutKeySchedule: true},
	)
	for _, shape := range shapes {
		compiled := testCompileShape(t, shape)
		system, ok := compiled.(interface{ GetR1Cs() []constraint.R1C })
		if !ok {
			t.Fatalf("%T is no R1CS", compiled)
		}
		read := map[uint32]bool{}
		for _, r1c := range system.GetR1Cs() {
			for _, expression := range []constraint.LinearExpression{r1c.L, r1c.R, r1c.O} {
				for _, term := range expression {
					read[term.VID] = true
				}
			}
		}
		// wire 0 is the constant one; the statement's elements are the public wires after it
		publics := compiled.GetNbPublicVariables() - 1
		z1From, z1To := testZ1InputPositions(shape, publics)
		var unread []int
		for position := range publics {
			if !read[uint32(position+1)] && (position < z1From || z1To <= position) {
				unread = append(unread, position)
			}
		}
		if len(unread) != 0 {
			t.Errorf("%s: public inputs %v appear in no constraint", partShapeName(shape), unread)
		}
	}
}

// pi3's peak memory as a prover host sees it: a process that only loads the compiled circuit, the
// proving key and the witness, and proves (TestMeasureProveOnly). SMTPPROOF_BENCH_LEG names the leg,
// tls13-aes by default, tls13-chacha or tls12-aes, and SMTPPROOF_BENCH_DATA set takes DATA's pi3 over
// BDAT's. D-SMTP-16's send sizes the part. The setup at pi3's size runs before the first iteration and
// takes minutes, so this runs only when asked for, as go test -run '^$' -bench BenchmarkPi3Memory.
func BenchmarkPi3Memory(b *testing.B) {
	directory := b.TempDir()
	prepare := exec.Command(os.Args[0], "-test.run=^TestPreparePi3$", "-test.v", "-test.timeout=0")
	prepare.Env = append(os.Environ(), "SMTPPROOF_PREPARE_DIR="+directory)
	if output, err := prepare.CombinedOutput(); err != nil {
		b.Fatalf("preparing pi3: %v: %s", err, output)
	}
	peakPattern := regexp.MustCompile(`prove-only: .* peak (\d+) MiB`)
	peak := 0
	b.ResetTimer()
	for range b.N {
		command := exec.Command(os.Args[0], "-test.run=^TestMeasureProveOnly$", "-test.v", "-test.timeout=0")
		command.Env = append(os.Environ(), "SMTPPROOF_PROVE_DIR="+directory)
		output, err := command.CombinedOutput()
		if err != nil {
			b.Fatalf("proving pi3: %v: %s", err, output)
		}
		match := peakPattern.FindSubmatch(output)
		if match == nil {
			b.Fatalf("no peak in %s", output)
		}
		mebibytes, err := strconv.Atoi(string(match[1]))
		if err != nil {
			b.Fatal(err)
		}
		peak = max(peak, mebibytes)
	}
	b.ReportMetric(float64(peak), "peak-MiB")
}

// BenchmarkPi3Memory's preparation, in a process of its own so its memory is not the prover's: pi3 of
// D-SMTP-16's send on one leg, set up on its production shape, written where TestMeasureProveOnly
// reads it.
func TestPreparePi3(t *testing.T) {
	directory := os.Getenv("SMTPPROOF_PREPARE_DIR")
	if directory == "" {
		t.Skip("run by BenchmarkPi3Memory")
	}
	legName := os.Getenv("SMTPPROOF_BENCH_LEG")
	if legName == "" {
		legName = "tls13-aes"
	}
	mode := partModeBdat
	if os.Getenv("SMTPPROOF_BENCH_DATA") != "" {
		mode = partModeData
	}
	for _, leg := range testTlsLegs() {
		if strings.ReplaceAll(leg.name, " ", "-") != legName {
			continue
		}
		job, settings := testSpeedGateJob(mode)
		send := testRunSend(t, leg, testMxDefaults(), settings, job)
		testExpectOneTransaction(t, leg, send, job)
		for i, statement := range send.backend.statements {
			if statement.index != 3 {
				continue
			}
			shape, err := partShapeFor(statement)
			if err != nil {
				t.Fatal(err)
			}
			keys := testSetup(t, shape)
			circuit, err := partAssignment(shape, statement)
			if err != nil {
				t.Fatal(err)
			}
			assignWitness(circuit, statement, send.backend.proved[i])
			full, err := frontend.NewWitness(circuit, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			for name, value := range map[string]interface {
				WriteTo(w io.Writer) (int64, error)
			}{"compiled": keys.compiled, "key": keys.provingKey, "witness": full} {
				file, err := os.Create(filepath.Join(directory, name))
				if err != nil {
					t.Fatal(err)
				}
				writer := bufio.NewWriterSize(file, 1024*1024)
				if _, err := value.WriteTo(writer); err != nil {
					t.Fatal(err)
				}
				if err := writer.Flush(); err != nil {
					t.Fatal(err)
				}
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
			}
			t.Logf("pi3 on %s, mode %d: %s, %d constraints", leg.name, mode, partShapeName(shape), keys.compiled.GetNbConstraints())
			return
		}
	}
	t.Fatalf("no pi3 on leg %s", legName)
}
