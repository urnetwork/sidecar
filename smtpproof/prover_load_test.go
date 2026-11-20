// The loader's memory rule on a fake source and a fake clock (DESIGN-DETAILS 3.2.8): loaded shapes and
// proofs in flight never charge past MemoryMaxByteCount, a shape a proof holds is never unloaded, an idle
// shape goes after ShapeIdleTimeout and the heap returns once the last does, and a cancelled proof returns
// its charge. Whether a load would wait is read deterministically: a load under a context already ended
// fails with it exactly when it must wait, and charges nothing then.

package smtpproof

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	gnarkwitness "github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The default budget and charges in MiB, so that a charge reads as its default's figure: two loaded shapes and
// one proof fill it (TestTheDefaultBudgetHoldsTwoShapesAndOneProof).
func testLoaderSettings() *ProverSettings {
	settings := DefaultProverSettings()
	settings.MemoryMaxByteCount /= 1024 * 1024
	settings.ShapeMemoryByteCount /= 1024 * 1024
	settings.PartMemoryByteCount /= 1024 * 1024
	settings.ShapeIdleTimeout = 2 * time.Minute
	return settings
}

// A loaded shape's charge and a proof's, as settings give them.
func testCharges(settings *ProverSettings) (int64, int64) {
	return settings.ShapeMemoryByteCount, settings.PartMemoryByteCount
}

// The default budget keeps the meaning DESIGN.md §5.4 and DESIGN-DETAILS 3.2.8 give it, two loaded shapes, the one
// proving and the next, and one proof in flight (QD-1115), so a charge's default is never raised without the
// budget: BenchmarkPartMemory holds each charge to what it measures.
func TestTheDefaultBudgetHoldsTwoShapesAndOneProof(t *testing.T) {
	settings := DefaultProverSettings()
	shape, part := testCharges(settings)
	if settings.MemoryMaxByteCount != 2*shape+part {
		t.Errorf("MemoryMaxByteCount's %d MiB is not two loaded shapes at %d MiB and one proof at %d MiB", settings.MemoryMaxByteCount/1024/1024, shape/1024/1024, part/1024/1024)
	}
	if settings.ProveConcurrency != 1 {
		t.Errorf("ProveConcurrency's default %d is past the one proof the default budget holds", settings.ProveConcurrency)
	}
}

// A loader on a fake clock, whose loads are counted by shape and whose heap returns are counted.
type testLoader struct {
	loader *proverLoader
	clock  *sidecartest.FakeClock

	stateLock sync.Mutex
	loads     map[string]int
	frees     int
	collects  int
}

func newTestLoader(t *testing.T, settings *ProverSettings) *testLoader {
	t.Helper()
	clock := sidecartest.NewFakeClock(time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC))
	loader := &testLoader{clock: clock, loads: map[string]int{}}
	loader.loader = newProverLoader(settings, clock)
	loader.loader.freeMemory = func() {
		loader.stateLock.Lock()
		defer loader.stateLock.Unlock()
		loader.frees += 1
	}
	loader.loader.collect = func() {
		loader.stateLock.Lock()
		defer loader.stateLock.Unlock()
		loader.collects += 1
	}
	return loader
}

func (self *testLoader) load(key string) func() (*shapeKeys, error) {
	return func() (*shapeKeys, error) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.loads[key] += 1
		return &shapeKeys{shape: &partShape{}}, nil
	}
}

func (self *testLoader) loadCount(key string) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.loads[key]
}

// The loaded shapes' keys in order, and what is charged.
func (self *testLoader) state() ([]string, int64) {
	keys, charged := self.loader.loaded()
	slices.Sort(keys)
	return keys, charged
}

// Takes a shape's charge, failing the test if it would wait.
func (self *testLoader) take(t *testing.T, key string) *loadedShape {
	t.Helper()
	shape, err := self.loader.acquire(context.Background(), key, self.load(key))
	if err != nil {
		t.Fatalf("%s: %v", key, err)
	}
	return shape
}

// Whether a shape's charge would wait now: a load under an ended context fails with it exactly then.
func (self *testLoader) wouldWait(t *testing.T, key string) bool {
	t.Helper()
	ended, cancel := context.WithCancel(context.Background())
	cancel()
	shape, err := self.loader.acquire(ended, key, self.load(key))
	switch {
	case errors.Is(err, context.Canceled):
		return true
	case err != nil:
		t.Fatalf("%s: %v", key, err)
	}
	self.loader.release(shape)
	return false
}

func (self *testLoader) expect(t *testing.T, step string, keys []string, charged int64) {
	t.Helper()
	gotKeys, gotCharged := self.state()
	if !slices.Equal(gotKeys, keys) || gotCharged != charged {
		t.Errorf("%s: loaded %v charging %d, want %v charging %d", step, gotKeys, gotCharged, keys, charged)
	}
	if max := self.loader.settings.MemoryMaxByteCount; max < gotCharged {
		t.Errorf("%s: %d charged past the budget's %d", step, gotCharged, max)
	}
}

func TestTheLoaderNeverChargesPastTheBudget(t *testing.T) {
	settings := testLoaderSettings()
	shape, part := testCharges(settings)
	loader := newTestLoader(t, settings)
	a := loader.take(t, "a")
	loader.expect(t, "a proving", []string{"a"}, shape+part)

	// a second shape and proof beside a's would pass the budget, and a is in use, so b waits and nothing goes
	if !loader.wouldWait(t, "b") {
		t.Fatal("b loaded beside a proof of a")
	}
	loader.expect(t, "b waiting", []string{"a"}, shape+part)
	if loader.loadCount("b") != 0 {
		t.Error("a load that waits read its shape")
	}

	// once a's proof ends, a stays loaded and b loads beside it: two shapes and one proof fill the budget
	loader.loader.release(a)
	b := loader.take(t, "b")
	loader.expect(t, "b proving", []string{"a", "b"}, 2*shape+part)

	// a third shape while b proves needs b's room, which b's proof holds: c waits, and a, idle, stays
	if !loader.wouldWait(t, "c") {
		t.Fatal("c loaded beside a proof of b")
	}
	loader.expect(t, "c waiting", []string{"a", "b"}, 2*shape+part)

	// with b's proof done, c takes the place of the least recently used shape, a
	loader.loader.release(b)
	c := loader.take(t, "c")
	loader.expect(t, "c proving", []string{"b", "c"}, 2*shape+part)
	loader.loader.release(c)

	// a proof of a shape already loaded charges only the proof
	again := loader.take(t, "b")
	loader.expect(t, "b again", []string{"b", "c"}, 2*shape+part)
	loader.loader.release(again)
	if loader.loadCount("b") != 1 || loader.loadCount("a") != 1 || loader.loadCount("c") != 1 {
		t.Errorf("loads %v", loader.loads)
	}
}

func TestTheLoaderNeverUnloadsAShapeInUse(t *testing.T) {
	settings := testLoaderSettings()
	shape, part := testCharges(settings)
	// room for two shapes and two proofs, and for no third shape beside them
	settings.MemoryMaxByteCount = 2*shape + 2*part
	loader := newTestLoader(t, settings)
	a := loader.take(t, "a")
	b := loader.take(t, "b")
	loader.expect(t, "a and b proving", []string{"a", "b"}, 2*shape+2*part)
	// both shapes are held, so a third waits however long ago they were used
	if !loader.wouldWait(t, "c") {
		t.Fatal("c loaded over two shapes in use")
	}
	loader.loader.release(a)
	// a is idle now, and goes for c; b stays
	c := loader.take(t, "c")
	loader.expect(t, "b and c proving", []string{"b", "c"}, 2*shape+2*part)
	loader.loader.release(b)
	loader.loader.release(c)
	loader.expect(t, "idle", []string{"b", "c"}, 2*shape)
}

func TestTheLoaderUnloadsAnIdleShapeAndThenReturnsTheHeap(t *testing.T) {
	settings := testLoaderSettings()
	shape, part := testCharges(settings)
	loader := newTestLoader(t, settings)
	a := loader.take(t, "a")
	loader.loader.release(a)
	loader.clock.Advance(time.Minute)
	b := loader.take(t, "b")
	loader.loader.release(b)
	loader.expect(t, "both idle", []string{"a", "b"}, 2*shape)

	// a's two minutes end first, and the heap stays: b is loaded
	loader.clock.Advance(time.Minute)
	loader.expect(t, "a timed out", []string{"b"}, shape)
	if loader.frees != 0 {
		t.Errorf("%d heap returns with a shape loaded", loader.frees)
	}
	// a use restarts b's timer
	again := loader.take(t, "b")
	loader.clock.Advance(time.Hour)
	loader.expect(t, "b in use", []string{"b"}, shape+part)
	loader.loader.release(again)
	loader.clock.Advance(2*time.Minute - time.Second)
	loader.expect(t, "b not yet idle long enough", []string{"b"}, shape)
	loader.clock.Advance(time.Second)
	loader.expect(t, "b timed out", nil, 0)
	if loader.frees != 1 {
		t.Errorf("%d heap returns, want one when the last shape went", loader.frees)
	}
}

func TestTheLoaderUnloadsAtOnceWithNoIdleTimeout(t *testing.T) {
	settings := testLoaderSettings()
	settings.ShapeIdleTimeout = 0
	loader := newTestLoader(t, settings)
	a := loader.take(t, "a")
	loader.loader.release(a)
	loader.expect(t, "released", nil, 0)
	if loader.frees != 1 {
		t.Errorf("%d heap returns", loader.frees)
	}
}

func TestACancelledProofReturnsItsCharge(t *testing.T) {
	settings := testLoaderSettings()
	shape, part := testCharges(settings)
	loader := newTestLoader(t, settings)
	started := make(chan struct{})
	unblock := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	proved := make(chan error, 1)
	go func() {
		_, err := loader.loader.prove(ctx, "a", loader.load("a"), func(keys *shapeKeys) ([]byte, error) {
			close(started)
			<-unblock
			return []byte("proof"), nil
		})
		proved <- err
	}()
	<-started
	cancel()
	if err := <-proved; !errors.Is(err, context.Canceled) {
		t.Fatalf("a cancelled proof returned %v", err)
	}
	// gnark's proof cannot stop, so its charge stays until it ends
	loader.expect(t, "cancelled, still proving", []string{"a"}, shape+part)
	if !loader.wouldWait(t, "b") {
		t.Error("b loaded beside a proof that still runs")
	}
	close(unblock)
	// and returns then: b's load waits for it and takes its place
	b, err := loader.loader.acquire(context.Background(), "b", loader.load("b"))
	if err != nil {
		t.Fatal(err)
	}
	loader.expect(t, "b after the cancelled proof", []string{"a", "b"}, 2*shape+part)
	loader.loader.release(b)
	if loader.collects != 1 {
		t.Errorf("%d collections, want one after the proof", loader.collects)
	}
}

func TestALoaderWithNoRoomForAProofRefusesEveryPart(t *testing.T) {
	settings := testLoaderSettings()
	shape, part := testCharges(settings)
	settings.MemoryMaxByteCount = shape + part - 1
	loader := newTestLoader(t, settings)
	if _, err := loader.loader.acquire(context.Background(), "a", loader.load("a")); err == nil {
		t.Fatal("a proof was charged past the budget")
	}
	if loader.loadCount("a") != 0 {
		t.Error("a refused load read its shape")
	}
}

func TestAFailedLoadIsNotKeptAndReturnsItsCharge(t *testing.T) {
	loader := newTestLoader(t, testLoaderSettings())
	failing := func() (*shapeKeys, error) {
		return nil, errNoKeys
	}
	if _, err := loader.loader.acquire(context.Background(), "a", failing); !errors.Is(err, errNoKeys) {
		t.Fatalf("err %v", err)
	}
	loader.expect(t, "after the failure", nil, 0)
	// the shape may be cached by now, and is loaded again
	a := loader.take(t, "a")
	loader.loader.release(a)
	if loader.loadCount("a") != 1 {
		t.Errorf("%d loads", loader.loadCount("a"))
	}
}

func TestProofsOfOneShapeShareItsLoad(t *testing.T) {
	settings := testLoaderSettings()
	shape, part := testCharges(settings)
	settings.MemoryMaxByteCount = shape + 2*part
	loader := newTestLoader(t, settings)
	first := loader.take(t, "a")
	second := loader.take(t, "a")
	loader.expect(t, "two proofs of a", []string{"a"}, shape+2*part)
	if !loader.wouldWait(t, "a") {
		t.Error("a third proof was charged past the budget")
	}
	loader.loader.release(first)
	loader.loader.release(second)
	if loader.loadCount("a") != 1 {
		t.Errorf("%d loads", loader.loadCount("a"))
	}
}

// What a proof takes over its loaded shape under the loader's rule, a collection after each proof
// (DESIGN-DETAILS 3.2.8), held to PartMemoryByteCount, and what the loaded shape takes, held to
// ShapeMemoryByteCount: either over its default fails, which says to raise it. One unit, the body shape of the
// family SMTPPROOF_BENCH_MEMORY names (aes128gcm or chacha20), is set up in a process of its own; a fresh
// process then loads its compiled circuit and its proving key's dump as a prover host's cache holds them,
// streamed, and proves at least three times back to back through a loader, reading its peak resident memory
// after the load and after each proof. The setup takes minutes, so this runs only when asked for:
// SMTPPROOF_BENCH_MEMORY=aes128gcm go test -run '^$' -bench BenchmarkPartMemory.
func BenchmarkPartMemory(b *testing.B) {
	if os.Getenv("SMTPPROOF_BENCH_MEMORY") == "" {
		b.Skip("set SMTPPROOF_BENCH_MEMORY to aes128gcm or chacha20 to run")
	}
	directory := b.TempDir()
	prepare := exec.Command(os.Args[0], "-test.run=^TestPreparePartMemory$", "-test.v", "-test.timeout=0")
	prepare.Env = append(os.Environ(), "SMTPPROOF_PREPARE_DIR="+directory)
	if output, err := prepare.CombinedOutput(); err != nil {
		b.Fatalf("preparing a unit: %v: %s", err, output)
	}
	b.ResetTimer()
	command := exec.Command(os.Args[0], "-test.run=^TestPartMemoryProofs$", "-test.v", "-test.timeout=0")
	command.Env = append(os.Environ(), "SMTPPROOF_PROVE_DIR="+directory, "SMTPPROOF_PROOF_COUNT="+strconv.Itoa(max(b.N, 3)))
	output, err := command.CombinedOutput()
	b.StopTimer()
	if err != nil {
		b.Fatalf("proving: %v: %s", err, output)
	}
	match := regexp.MustCompile(`part-memory: shape (\d+) MiB, proof (\d+) MiB`).FindSubmatch(output)
	if match == nil {
		b.Fatalf("no figures in %s", output)
	}
	shapeMebibytes, _ := strconv.ParseInt(string(match[1]), 10, 64)
	proofMebibytes, _ := strconv.ParseInt(string(match[2]), 10, 64)
	b.ReportMetric(float64(shapeMebibytes), "shape-MiB")
	b.ReportMetric(float64(proofMebibytes), "proof-MiB")
	settings := DefaultProverSettings()
	if settings.ShapeMemoryByteCount < shapeMebibytes*1024*1024 {
		b.Errorf("a loaded shape took %d MiB, past ShapeMemoryByteCount's %d MiB: raise its default", shapeMebibytes, settings.ShapeMemoryByteCount/1024/1024)
	}
	if settings.PartMemoryByteCount < proofMebibytes*1024*1024 {
		b.Errorf("a proof took %d MiB over its shape, past PartMemoryByteCount's %d MiB: raise its default", proofMebibytes, settings.PartMemoryByteCount/1024/1024)
	}
}

// This process's peak resident memory so far, in octets: getrusage's maxrss, in octets on darwin and KiB
// elsewhere.
func testPeakResidentBytes(t *testing.T) int64 {
	t.Helper()
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "darwin" {
		return int64(usage.Maxrss)
	}
	return int64(usage.Maxrss) * 1024
}

// BenchmarkPartMemory's preparation, in a process of its own so that its memory is not the prover's: a unit
// of the family's body shape, set up by gnark's one-party test setup, written as a host's cache holds it, the
// compiled circuit and the proving key's dump, beside a measuring part's full witness.
func TestPreparePartMemory(t *testing.T) {
	directory := os.Getenv("SMTPPROOF_PREPARE_DIR")
	if directory == "" {
		t.Skip("run by BenchmarkPartMemory")
	}
	proof := DefaultProofSettings()
	entry := proof.shape(ShapeKindBody, ShapeFamily(os.Getenv("SMTPPROOF_BENCH_MEMORY")), 0)
	if entry == nil {
		t.Fatalf("no body shape of family %q", os.Getenv("SMTPPROOF_BENCH_MEMORY"))
	}
	shape := newPartShape(proof, entry)
	statement, witness, err := newMeasurePart(proof, shape)
	if err != nil {
		t.Fatal(err)
	}
	keys := testSetup(t, shape)
	circuit, err := partAssignment(shape, statement)
	if err != nil {
		t.Fatal(err)
	}
	assignWitness(circuit, statement, witness)
	full, err := frontend.NewWitness(circuit, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, write func(writer io.Writer) error) {
		file, err := os.Create(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		writer := bufio.NewWriterSize(file, 1024*1024)
		if err := write(writer); err != nil {
			t.Fatal(err)
		}
		if err := writer.Flush(); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	write("compiled", func(writer io.Writer) error {
		_, err := keys.compiled.WriteTo(writer)
		return err
	})
	write("dump", keys.provingKey.WriteDump)
	write("witness", func(writer io.Writer) error {
		_, err := full.WriteTo(writer)
		return err
	})
}

// BenchmarkPartMemory's prover: the shape loaded as keyCache.loadShape reads it, then its proofs through a
// loader on the default budget, reading the peak resident memory after the load and after each proof.
func TestPartMemoryProofs(t *testing.T) {
	directory := os.Getenv("SMTPPROOF_PROVE_DIR")
	if directory == "" {
		t.Skip("run by BenchmarkPartMemory")
	}
	count, err := strconv.Atoi(os.Getenv("SMTPPROOF_PROOF_COUNT"))
	if err != nil {
		t.Fatal(err)
	}
	read := func(name string, read func(reader io.Reader) error) {
		file, err := os.Open(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		if err := read(bufio.NewReaderSize(file, 1024*1024)); err != nil {
			t.Fatal(err)
		}
	}
	before := testPeakResidentBytes(t)
	compiled := groth16.NewCS(ecc.BN254)
	read("compiled", func(reader io.Reader) error {
		_, err := compiled.ReadFrom(reader)
		return err
	})
	provingKey := groth16.NewProvingKey(ecc.BN254)
	read("dump", provingKey.ReadDump)
	full, err := gnarkwitness.New(ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	read("witness", func(reader io.Reader) error {
		_, err := full.ReadFrom(reader)
		return err
	})
	runtime.GC()
	loaded := testPeakResidentBytes(t)
	keys := &shapeKeys{compiled: compiled, provingKey: provingKey}
	loader := newProverLoader(DefaultProverSettings(), sidecar.RealClock{})
	peak := loaded
	for range count {
		_, err := loader.prove(context.Background(), "unit", func() (*shapeKeys, error) {
			return keys, nil
		}, func(keys *shapeKeys) ([]byte, error) {
			if _, err := groth16.Prove(keys.compiled, keys.provingKey, full); err != nil {
				return nil, err
			}
			return []byte("proved"), nil
		})
		if err != nil {
			t.Fatal(err)
		}
		peak = max(peak, testPeakResidentBytes(t))
	}
	t.Logf("part-memory: shape %d MiB, proof %d MiB", (loaded-before)/1024/1024, (peak-loaded)/1024/1024)
}
