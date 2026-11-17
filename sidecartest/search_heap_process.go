// A search heap process (search_heap.go; FS-77, FS-109): the test binary run again for one test, so a search's heap is
// sampled where nothing another test of the binary left running, a world or a goroutine, allocates beside it or frees
// during it, as evsgit's world runs its hooks in helper processes of the binary. The test calls RunSearchHeapProcess
// with its body: in the parent that starts the process and waits for it, reporting what it printed and failing as it
// failed; in the process it runs the body, whose samplers alone may answer their checks.
//
//	the process   the test binary with -test.run naming the one test and -test.count 1, and the variable below naming
//	              it, which InSearchHeapProcess reads with both flags, so a process running any other test is none
//	its parent    holds the only end of a pipe that is the process's standard input, which the process watches: when
//	              the parent ends, by a timeout's panic or a kill, the process ends too, and never runs on unseen
//	its deadline  the parent's less TimeoutMargin, so a process that hangs panics with its own goroutines' stacks for the
//	              parent to report, rather than the parent's panic showing only its wait
//
// A top-level test only: -test.run would name a subtest by its parent's run too, and run the parent's body again.

package sidecartest

import (
	"bytes"
	"flag"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// Names the test a search heap process runs, in the process's environment.
const searchHeapProcessVariable = "SIDECARTEST_SEARCH_HEAP_PROCESS"

// What a search heap process exits with when its parent ended before it.
const searchHeapOrphanExitCode = 3

// How a search heap process runs.
type SearchHeapProcessSettings struct {
	// How long before the parent's deadline the process's own test times out: time for its panic to write every
	// goroutine's stack and for the parent to report it. A test with less left than this gives the process all of it.
	TimeoutMargin time.Duration
}

func DefaultSearchHeapProcessSettings() *SearchHeapProcessSettings {
	return &SearchHeapProcessSettings{
		// a dump of a schedule's goroutines takes well under a second, even on a loaded host
		TimeoutMargin: 30 * time.Second,
	}
}

// Whether this process is a search heap process: the test binary run for the one test the variable names, alone.
func InSearchHeapProcess() bool {
	name := os.Getenv(searchHeapProcessVariable)
	if name == "" {
		return false
	}
	run, count := flag.Lookup("test.run"), flag.Lookup("test.count")
	return run != nil && count != nil && run.Value.String() == searchHeapProcessRun(name) && count.Value.String() == "1"
}

// The -test.run that names test name alone.
func searchHeapProcessRun(name string) string {
	return "^" + regexp.QuoteMeta(name) + "$"
}

// Runs body as t in a search heap process: here when this is t's, else in one started for t and waited for, its
// output logged, t failing as it failed, skipped as it was skipped, and failing when it ran no test of t's name.
// settings nil takes the defaults.
func RunSearchHeapProcess(t *testing.T, settings *SearchHeapProcessSettings, body func(t *testing.T)) {
	t.Helper()
	name := t.Name()
	if os.Getenv(searchHeapProcessVariable) == name {
		if !InSearchHeapProcess() {
			t.Fatalf("%s runs in its search heap process alone: -test.run %s and -test.count 1", name, searchHeapProcessRun(name))
		}
		watchSearchHeapParent()
		body(t)
		return
	}
	if strings.Contains(name, "/") {
		t.Fatalf("%s is a subtest: a search heap process runs a top-level test", name)
	}
	if settings == nil {
		settings = DefaultSearchHeapProcessSettings()
	}
	output := &bytes.Buffer{}
	process, _, err := startSearchHeapProcess(t, name, settings, output)
	if err != nil {
		t.Fatalf("%s's search heap process did not start: %v", name, err)
	}
	err = process.Wait()
	t.Logf("%s's search heap process:\n%s", name, searchHeapProcessQuoted(output.Bytes()))
	switch verdict := searchHeapProcessVerdict(name, output.Bytes()); {
	case err != nil:
		t.Fatalf("%s's search heap process failed: %v", name, err)
	case verdict == "SKIP":
		t.Skipf("%s's search heap process skipped it", name)
	case verdict != "PASS":
		t.Fatalf("%s's search heap process ran no test of that name", name)
	}
}

// Starts the search heap process for test name, its output written to output, and answers it with its parent's end of
// its standard input: a pipe only this process holds, which Wait closes once the process ended, and whose close the
// process takes for its parent's end. The process is killed when t's context ends.
func startSearchHeapProcess(t *testing.T, name string, settings *SearchHeapProcessSettings, output io.Writer) (*exec.Cmd, io.Closer, error) {
	binary, err := os.Executable()
	if err != nil {
		return nil, nil, err
	}
	arguments := []string{"-test.run=" + searchHeapProcessRun(name), "-test.count=1", "-test.v=true"}
	if testing.Short() {
		arguments = append(arguments, "-test.short=true")
	}
	if deadline, ok := t.Deadline(); ok {
		timeout := time.Until(deadline)
		if settings.TimeoutMargin < timeout {
			timeout -= settings.TimeoutMargin
		}
		if 0 < timeout {
			arguments = append(arguments, "-test.timeout="+timeout.String())
		}
	}
	command := exec.CommandContext(t.Context(), binary, arguments...)
	command.Env = append(os.Environ(), searchHeapProcessVariable+"="+name)
	command.Stdout = output
	command.Stderr = output
	parentEnd, err := command.StdinPipe()
	if err != nil {
		return nil, nil, err
	}
	if err := command.Start(); err != nil {
		return nil, nil, err
	}
	return command, parentEnd, nil
}

// "PASS", "FAIL" or "SKIP", as the process's verbose output reports test name, or "" when it reports no such test.
func searchHeapProcessVerdict(name string, output []byte) string {
	verdict := regexp.MustCompile(`(?m)^--- (PASS|FAIL|SKIP): ` + regexp.QuoteMeta(name) + ` \(`).FindSubmatch(output)
	if verdict == nil {
		return ""
	}
	return string(verdict[1])
}

// The process's output as the parent logs it: each line marked, so no line of it reads as a test event of the
// parent's (test2json takes an indented "--- PASS" for a subtest's).
func searchHeapProcessQuoted(output []byte) string {
	var quoted strings.Builder
	for _, line := range strings.SplitAfter(string(output), "\n") {
		if line == "" {
			continue
		}
		quoted.WriteString("| ")
		quoted.WriteString(line)
	}
	if !strings.HasSuffix(quoted.String(), "\n") {
		quoted.WriteString("\n")
	}
	return quoted.String()
}

var searchHeapParentWatchOnce sync.Once

// Ends this process once its parent has: its standard input is a pipe only the parent holds, which reads at its end
// when the parent ends. The read blocks in a system call, which allocates nothing a sample sees, its byte allocated
// here before the body's samplers begin.
func watchSearchHeapParent() {
	searchHeapParentWatchOnce.Do(func() {
		buffer := make([]byte, 1)
		go func() {
			// the parent writes nothing, so any answer is its end
			os.Stdin.Read(buffer)
			os.Exit(searchHeapOrphanExitCode)
		}()
	})
}
