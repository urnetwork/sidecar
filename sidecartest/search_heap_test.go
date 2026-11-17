package sidecartest

// The heap sampler's own cases (search_heap.go, search_heap_process.go): what the process's heap counts that is no
// search's, from another test's goroutine and from a sibling search at work, and how a search heap process and a
// sampler of searches at once leave each out while a step's own heap still fails its budget. Every allocation is far
// from the budget it is held to either way, so a collector's timing cannot move a verdict, and every order is set by
// channels.

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"testing"
	"time"
)

// What a goroutine outside a step allocates past the budgets the cases hold a step to.
const searchHeapTestForeignByteCount = 64 * 1024 * 1024

// A step's budget in the cases.
const searchHeapTestBudgetByteCount = 8 * 1024 * 1024

// A goroutine standing for one an earlier test of the binary left running: it allocates when told and keeps what it
// allocated until the test ends.
type searchHeapLeftover struct {
	grows chan int
	grown chan struct{}
}

func startSearchHeapLeftover(t *testing.T) *searchHeapLeftover {
	leftover := &searchHeapLeftover{grows: make(chan int), grown: make(chan struct{})}
	stop := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		held := [][]byte{}
		for {
			select {
			case byteCount := <-leftover.grows:
				held = append(held, make([]byte, byteCount))
				leftover.grown <- struct{}{}
			case <-stop:
				runtime.KeepAlive(held)
				return
			}
		}
	}()
	t.Cleanup(func() {
		close(stop)
		<-stopped
	})
	return leftover
}

// Has the leftover allocate byteCount more and keep it, answering once it holds it. A nil leftover, as a search heap
// process has, does nothing.
func (self *searchHeapLeftover) grow(byteCount int) {
	if self == nil {
		return
	}
	self.grows <- byteCount
	<-self.grown
}

// A step holding 1 MiB at its one sample, while leftover, nil for none, grows past the budget between the sampler's
// start and the sample: FS-109's step as the orchestrator read its failure at abd1bdee.
func searchHeapTestStep(leftover *searchHeapLeftover) (*SearchHeapSampler, int64) {
	sampler := NewSearchHeapSampler()
	leftover.grow(searchHeapTestForeignByteCount)
	held := make([]byte, 1024*1024)
	growth := sampler.Sample("step")
	runtime.KeepAlive(held)
	return sampler, growth
}

// In the test binary's own process the sampler counts what another test's goroutine allocates through the step as the
// step's, so its check there refuses to answer rather than blame the step.
func TestSearchHeapSamplerCountsAnotherGoroutinesHeap(t *testing.T) {
	leftover := startSearchHeapLeftover(t)
	sampler, growth := searchHeapTestStep(leftover)
	if growth < searchHeapTestForeignByteCount {
		t.Fatalf("the control failed: a step beside a goroutine that grew %d B measured %d B", searchHeapTestForeignByteCount, growth)
	}
	if err := sampler.CheckWithin("a step holding 1 MiB", searchHeapTestBudgetByteCount); !errors.Is(err, ErrSearchHeapRefused) {
		t.Fatalf("a check in a process other tests share answered %v", err)
	}
}

// The same step in its search heap process: the leftover is the test binary's, none of the process's, and the step's
// check passes on the step's own heap. Before search heap processes the step sampled in the binary's process, where it
// failed past its budget by the leftover's 64 MiB.
func TestSearchHeapProcessLeavesOutALeftover(t *testing.T) {
	var leftover *searchHeapLeftover
	if !InSearchHeapProcess() {
		leftover = startSearchHeapLeftover(t)
		leftover.grow(searchHeapTestForeignByteCount)
	}
	RunSearchHeapProcess(t, nil, func(t *testing.T) {
		// nil here: the leftover lives in the parent only
		sampler, _ := searchHeapTestStep(leftover)
		if err := sampler.CheckWithin("a step holding 1 MiB", searchHeapTestBudgetByteCount); err != nil {
			t.Fatal(err)
		}
	})
}

// In its search heap process a step holding past its budget at a sample still fails, and one that dropped what it
// allocated before the sample does not: the forced collection frees it.
func TestSearchHeapProcessCheckHoldsAStepToItsBudget(t *testing.T) {
	RunSearchHeapProcess(t, nil, func(t *testing.T) {
		holding := NewSearchHeapSampler()
		held := make([]byte, searchHeapTestForeignByteCount)
		holding.Sample("holding")
		runtime.KeepAlive(held)
		held = nil
		err := holding.CheckWithin("a step holding 64 MiB", searchHeapTestBudgetByteCount)
		if err == nil || errors.Is(err, ErrSearchHeapRefused) {
			t.Fatalf("a step holding past its budget answered %v", err)
		}

		dropping := NewSearchHeapSampler()
		dropped := make([]byte, searchHeapTestForeignByteCount)
		runtime.KeepAlive(dropped)
		dropped = nil
		dropping.Sample("dropped")
		if err := dropping.CheckWithin("a step that dropped 64 MiB", searchHeapTestBudgetByteCount); err != nil {
			t.Fatal(err)
		}
	})
}

// An engine's slots as a case sets them: how many searches hold one, and a channel closed at the first hold, which
// a sampler of searches at once takes at each park.
type searchHeapTestSlots struct {
	stateLock   sync.Mutex
	holderCount int
	holdCount   int
	firstHeld   chan struct{}
}

func newSearchHeapTestSlots(holderCount int) *searchHeapTestSlots {
	return &searchHeapTestSlots{holderCount: holderCount, firstHeld: make(chan struct{})}
}

// See SearchHeapSlots.
func (self *searchHeapTestSlots) HoldSearchSlots() (int, func()) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.holdCount += 1
	if self.holdCount == 1 {
		close(self.firstHeld)
	}
	return self.holderCount, func() {}
}

func (self *searchHeapTestSlots) setHolderCount(holderCount int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.holderCount = holderCount
}

// Two searches at once on sampler, a on this goroutine and b on its own, each holding one of slots: b holds 64 MiB at
// work, past the budget, while a samples, and then samples itself, having let the 64 MiB go first with dropBefore and
// still holding it without.
func searchHeapTestSiblings(sampler *SearchHeapSampler, slots *searchHeapTestSlots, dropBefore bool) {
	working := make(chan struct{})
	ended := make(chan struct{})
	go func() {
		defer close(ended)
		defer sampler.SearchEnded()
		work := make([]byte, searchHeapTestForeignByteCount)
		close(working)
		// a has parked, its collection waiting on b, which holds a slot
		<-slots.firstHeld
		if dropBefore {
			runtime.KeepAlive(work)
			work = nil
		}
		sampler.SampleHoldingSlot("b")
		runtime.KeepAlive(work)
	}()
	<-working
	sampler.SampleHoldingSlot("a")
	sampler.SearchEnded()
	<-ended
}

// A sibling's work at another's sample is left out: a's sample waits for b to park, by which b let its 64 MiB go, and
// the collection then frees it. A sampler of one search, as FS-109's searches at once had, counts it at a's sample.
func TestSearchHeapSamplerOfSearchesLeavesOutASiblingAtWork(t *testing.T) {
	RunSearchHeapProcess(t, nil, func(t *testing.T) {
		slots := newSearchHeapTestSlots(2)
		sampler := NewSearchHeapSamplerOfSearches(nil, slots)
		searchHeapTestSiblings(sampler, slots, true)
		if err := sampler.CheckWithin("searches at once", searchHeapTestBudgetByteCount); err != nil {
			t.Fatal(err)
		}
		if count := sampler.SampleCount(); count != 1 {
			t.Fatalf("a and b parked together took %d samples", count)
		}

		// the control: a sample of one search collects at once, b at work beside it
		alone := NewSearchHeapSampler()
		working := make(chan struct{})
		sampled := make(chan struct{})
		ended := make(chan struct{})
		go func() {
			defer close(ended)
			work := make([]byte, searchHeapTestForeignByteCount)
			close(working)
			<-sampled
			runtime.KeepAlive(work)
		}()
		<-working
		growth := alone.Sample("a")
		close(sampled)
		<-ended
		if growth < searchHeapTestForeignByteCount {
			t.Fatalf("the control failed: a sample beside a sibling holding %d B at work measured %d B", searchHeapTestForeignByteCount, growth)
		}
	})
}

// What a sibling still holds at its own sample counts at once: the check of searches at once still fails past its
// budget.
func TestSearchHeapSamplerOfSearchesCountsWhatASiblingHoldsAtItsSample(t *testing.T) {
	RunSearchHeapProcess(t, nil, func(t *testing.T) {
		slots := newSearchHeapTestSlots(2)
		sampler := NewSearchHeapSamplerOfSearches(nil, slots)
		searchHeapTestSiblings(sampler, slots, false)
		err := sampler.CheckWithin("searches at once", searchHeapTestBudgetByteCount)
		if err == nil || errors.Is(err, ErrSearchHeapRefused) {
			t.Fatalf("a sibling holding 64 MiB at its sample answered %v", err)
		}
	})
}

// A search holding a slot that ends with no sample, as one whose page fails, lets the parked be collected for at its
// end; and a search parked holding no slot, with no search holding one, is collected for at once.
func TestSearchHeapSamplerOfSearchesCollectsWhenTheLastHolderEnds(t *testing.T) {
	RunSearchHeapProcess(t, nil, func(t *testing.T) {
		slots := newSearchHeapTestSlots(2)
		sampler := NewSearchHeapSamplerOfSearches(nil, slots)
		sampled := make(chan struct{})
		go func() {
			defer close(sampled)
			sampler.SampleHoldingSlot("a")
		}()
		<-slots.firstHeld
		slots.setHolderCount(1)
		sampler.SearchEnded()
		<-sampled
		if count := sampler.SampleCount(); count != 1 {
			t.Fatalf("a parked search was collected for %d times once the other holder ended", count)
		}

		slots.setHolderCount(0)
		sampler.Sample("between pages")
		if count := sampler.SampleCount(); count != 2 {
			t.Fatalf("a search parked with no holder at work took %d samples in all", count)
		}
		if err := sampler.CheckWithin("searches at once", searchHeapTestBudgetByteCount); err != nil {
			t.Fatal(err)
		}
	})
}

// A sampler of searches at once given no slots refuses its check, even in a search heap process.
func TestSearchHeapSamplerOfSearchesRefusesNoSlots(t *testing.T) {
	RunSearchHeapProcess(t, nil, func(t *testing.T) {
		sampler := NewSearchHeapSamplerOfSearches(nil, nil)
		sampler.Sample("alone")
		if err := sampler.CheckWithin("searches at once", searchHeapTestBudgetByteCount); !errors.Is(err, ErrSearchHeapRefused) {
			t.Fatalf("a sampler with no slots answered %v", err)
		}
	})
}

// Not a test: in its own search heap process, a body that fails as planted, which TestSearchHeapProcessCarriesAFailure
// runs; anywhere else it does nothing.
func TestSearchHeapProcessFailingBody(t *testing.T) {
	if os.Getenv(searchHeapProcessVariable) != t.Name() {
		return
	}
	RunSearchHeapProcess(t, nil, func(t *testing.T) {
		t.Error("the planted failure")
	})
}

// A body that fails in its search heap process fails the process, whose output says why; a process for a test the
// binary has not runs nothing, which its verdict tells from a pass.
func TestSearchHeapProcessCarriesAFailure(t *testing.T) {
	cases := []struct {
		name    string
		verdict string
		failed  bool
		says    string
	}{
		{name: "TestSearchHeapProcessFailingBody", verdict: "FAIL", failed: true, says: "the planted failure"},
		{name: "TestSearchHeapProcessNoSuchTest", verdict: "", failed: false, says: "no tests to run"},
	}
	for _, c := range cases {
		output := &bytes.Buffer{}
		process, _, err := startSearchHeapProcess(t, c.name, DefaultSearchHeapProcessSettings(), output)
		if err != nil {
			t.Fatal(err)
		}
		err = process.Wait()
		if failed := err != nil; failed != c.failed || searchHeapProcessVerdict(c.name, output.Bytes()) != c.verdict || !bytes.Contains(output.Bytes(), []byte(c.says)) {
			t.Errorf("%s's process answered %v, verdict %q:\n%s", c.name, err, searchHeapProcessVerdict(c.name, output.Bytes()), output)
		}
	}
}

// A process's verbose output read for one test's verdict, and nothing taken for it from another's.
func TestSearchHeapProcessVerdicts(t *testing.T) {
	cases := []struct {
		output  string
		verdict string
	}{
		{output: "=== RUN   TestA\n--- PASS: TestA (0.01s)\nPASS\n", verdict: "PASS"},
		{output: "=== RUN   TestA\n    a_test.go:9: why\n--- FAIL: TestA (0.01s)\nFAIL\n", verdict: "FAIL"},
		{output: "=== RUN   TestA\n--- SKIP: TestA (0.00s)\nPASS\n", verdict: "SKIP"},
		{output: "=== RUN   TestAB\n--- PASS: TestAB (0.01s)\nPASS\n", verdict: ""},
		{output: "testing: warning: no tests to run\nPASS\n", verdict: ""},
		{output: "    | --- PASS: TestA (0.01s)\n", verdict: ""},
	}
	for _, c := range cases {
		if verdict := searchHeapProcessVerdict("TestA", []byte(c.output)); verdict != c.verdict {
			t.Errorf("%q read %q, not %q", c.output, verdict, c.verdict)
		}
	}
	if quoted := searchHeapProcessQuoted([]byte("--- PASS: TestA (0.01s)\nPASS")); quoted != "| --- PASS: TestA (0.01s)\n| PASS\n" {
		t.Errorf("the output quoted as %q", quoted)
	}
}

// The line TestSearchHeapProcessWaitingBody writes once its body runs.
const searchHeapTestWaitingLine = "search heap test: the body waits"

// Not a test: in its own search heap process, a body that says it runs and then waits on nothing that comes, which
// TestSearchHeapProcessEndsWithItsParent runs; anywhere else it does nothing.
func TestSearchHeapProcessWaitingBody(t *testing.T) {
	if os.Getenv(searchHeapProcessVariable) != t.Name() {
		return
	}
	RunSearchHeapProcess(t, nil, func(t *testing.T) {
		fmt.Fprintln(os.Stdout, searchHeapTestWaitingLine)
		<-t.Context().Done()
	})
}

// A search heap process whose parent's end of its standard input closes, as the parent's end closes it, ends: it
// never runs on unseen. The guard's firing fails the test, and the process is killed with the test's context.
func TestSearchHeapProcessEndsWithItsParent(t *testing.T) {
	reader, writer := io.Pipe()
	defer reader.Close()
	process, parentEnd, err := startSearchHeapProcess(t, "TestSearchHeapProcessWaitingBody", DefaultSearchHeapProcessSettings(), writer)
	if err != nil {
		t.Fatal(err)
	}
	lines := bufio.NewScanner(reader)
	for waiting := false; !waiting; {
		if !lines.Scan() {
			t.Fatalf("the process ended before its body ran: %v", lines.Err())
		}
		waiting = lines.Text() == searchHeapTestWaitingLine
	}
	go io.Copy(io.Discard, reader)
	parentEnd.Close()
	waited := make(chan error, 1)
	go func() {
		waited <- process.Wait()
		writer.Close()
	}()
	select {
	case err := <-waited:
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() != searchHeapOrphanExitCode {
			t.Fatalf("the process ended with %v, not its orphan's code %d", err, searchHeapOrphanExitCode)
		}
	case <-time.After(time.Minute):
		t.Fatal("the process ran on a minute after its parent's end of its input closed")
	}
}
