//go:build sidecar_check

// sidecar/test.sh (TEST-M0-04; D-TEST-1, R-TEST-9, D-TEST-4), run against a fixture module and a stub
// go that records each call: a failing phase ends the run with no footer of its own, a phase that would
// pass on a second call still fails the run, every go test carries -count=1, an unknown cadence is
// refused, an interrupt leaves no process behind, and the environment RUN-ALL hands over reaches each
// phase unchanged but for WARP_TEST_ENV_FAIL_FAST. The stub's failure lines stay inside these tests'
// captured output, as tests/RUN-ALL.md's clean-run criteria ask of synthetic failures.

package check

import (
	"bufio"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// How long a test waits on test.sh before it fails rather than hangs: a bound on a broken run, never
// the proof (CODESTYLE's tests).
const testShGuardTimeout = 2 * time.Minute

// The stub go: it appends one line per call, its directory, arguments, WARP_TEST_ENV_FAIL_FAST and
// GOMAXPROCS, then fails on call STUB_GO_FAIL_CALL, or on call STUB_GO_HANG_CALL starts a child that
// holds STUB_GO_ALIVE open and waits for it.
const testShStubGo = `#!/bin/bash
log=$STUB_GO_LOG
call=$(( $(wc -l < "$log") + 1 ))
printf '%s\t%s\t%s\t%s\n' "$(pwd)" "$*" "${WARP_TEST_ENV_FAIL_FAST-unset}" "${GOMAXPROCS-unset}" >> "$log"
if [ "${STUB_GO_FAIL_CALL:-0}" = "$call" ]; then
  echo "--- FAIL: TestPlanted (0.00s)"
  echo "FAIL"
  exit 1
fi
if [ "${STUB_GO_HANG_CALL:-0}" = "$call" ]; then
  sleep 1000 3>"$STUB_GO_ALIVE" &
  wait
fi
exit 0
`

// The fixture's Makefile: two modules, and make check, leaktest and stack-test as calls of the stub.
const testShFixtureMakefile = "GO ?= go\n\nmodules := . nested\n\n" +
	"check:\n\t$(GO) make-check\n\nleaktest:\n\t$(GO) make-leaktest\n\nstack-test:\n\t$(GO) make-stack-test\n"

// One run of test.sh in a fixture.
type testShRun struct {
	output   string
	exitCode int
	// each stub call: directory, arguments, WARP_TEST_ENV_FAIL_FAST and GOMAXPROCS
	calls [][]string
}

// A fixture checkout holding this repository's test.sh, the fixture Makefile and its two modules, and
// a stub go with an empty call log. Returns the checkout and the environment test.sh runs with.
func newTestShFixture(t *testing.T) (string, []string) {
	t.Helper()
	repository, err := thisCheckout()
	if err != nil {
		t.Fatal(err)
	}
	script, err := os.ReadFile(filepath.Join(repository.moduleDirectory, "test.sh"))
	if err != nil {
		t.Fatal(err)
	}
	top := t.TempDir()
	checkout := filepath.Join(top, "sidecar")
	for name, content := range map[string]string{
		"sidecar/test.sh":       string(script),
		"sidecar/Makefile":      testShFixtureMakefile,
		"sidecar/nested/README": "the fixture's second module\n",
		"bin/go":                testShStubGo,
		"stub-go.log":           "",
	} {
		path := filepath.Join(top, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	environment := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + top,
		"GO=" + filepath.Join(top, "bin", "go"),
		"STUB_GO_LOG=" + filepath.Join(top, "stub-go.log"),
		"GOMAXPROCS=3",
	}
	return checkout, environment
}

// The stub's calls, from its log.
func testShCalls(t *testing.T, checkout string) [][]string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(filepath.Dir(checkout), "stub-go.log"))
	if err != nil {
		t.Fatal(err)
	}
	calls := [][]string{}
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		if line != "" {
			calls = append(calls, strings.Split(line, "\t"))
		}
	}
	return calls
}

// Runs test.sh in checkout with arguments, under the guard.
func runTestSh(t *testing.T, checkout string, environment []string, arguments ...string) *testShRun {
	t.Helper()
	command := exec.Command("bash", append([]string{filepath.Join(checkout, "test.sh")}, arguments...)...)
	command.Env = environment
	command.Dir = checkout
	done := make(chan struct{})
	var output []byte
	var err error
	go func() {
		defer close(done)
		output, err = command.CombinedOutput()
	}()
	select {
	case <-done:
	case <-time.After(testShGuardTimeout):
		command.Process.Kill()
		t.Fatalf("test.sh %v did not end", arguments)
	}
	exitCode := 0
	if err != nil {
		exitError, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatal(err)
		}
		exitCode = exitError.ExitCode()
	}
	return &testShRun{output: string(output), exitCode: exitCode, calls: testShCalls(t, checkout)}
}

// A merge run with every phase passing: each module's race and testhooks runs in order, then the leak
// leg and make check, every go test with -count=1, the fail-fast setting exported and GOMAXPROCS
// inherited as it was.
func TestTestShRunsEveryMergePhaseWithCountOne(t *testing.T) {
	checkout, environment := newTestShFixture(t)
	run := runTestSh(t, checkout, environment)
	if run.exitCode != 0 {
		t.Fatalf("exit %d:\n%s", run.exitCode, run.output)
	}
	want := []struct {
		directory string
		arguments string
	}{
		{"sidecar", "test -race -count=1 -timeout 30m ./..."},
		{"sidecar", "test -race -count=1 -timeout 30m -tags sidecar_testhooks ./..."},
		{"nested", "test -race -count=1 -timeout 30m ./..."},
		{"nested", "test -race -count=1 -timeout 30m -tags sidecar_testhooks ./..."},
		{"sidecar", "test -race -count=1 -timeout 30m -tags sidecar_leaktest ./sidecartest/..."},
		{"sidecar", "make-check"},
	}
	if len(run.calls) != len(want) {
		t.Fatalf("%d calls, want %d: %v", len(run.calls), len(want), run.calls)
	}
	for index, call := range run.calls {
		if filepath.Base(call[0]) != want[index].directory || call[1] != want[index].arguments {
			t.Errorf("call %d: %s in %s, want %s in %s", index+1, call[1], filepath.Base(call[0]), want[index].arguments, want[index].directory)
		}
		if strings.HasPrefix(call[1], "test ") && !strings.Contains(call[1], " -count=1 ") {
			t.Errorf("call %d runs go test without -count=1: %s", index+1, call[1])
		}
		if call[2] != "1" {
			t.Errorf("call %d sees WARP_TEST_ENV_FAIL_FAST=%s", index+1, call[2])
		}
		if call[3] != "3" {
			t.Errorf("call %d sees GOMAXPROCS=%s, not the 3 the run inherited", index+1, call[3])
		}
	}
	for _, footer := range []string{"phase race . ok", "phase testhooks nested ok", "phase leak ok", "phase check ok"} {
		if !strings.Contains(run.output, footer) {
			t.Errorf("no footer %q:\n%s", footer, run.output)
		}
	}
	if !strings.Contains(run.output, "phase t3-suites: not run") || !strings.Contains(run.output, "not run, which is no pass: t3-suites") {
		t.Errorf("the missing server sibling is not reported as not run:\n%s", run.output)
	}
}

// A failing test fails the run: test.sh exits non-zero, prints no footer for the phase, and runs
// nothing after it.
func TestTestShFailingTestExitsNonZeroWithNoFooter(t *testing.T) {
	checkout, environment := newTestShFixture(t)
	run := runTestSh(t, checkout, append(environment, "STUB_GO_FAIL_CALL=2"))
	if run.exitCode == 0 {
		t.Fatalf("a failing phase exited 0:\n%s", run.output)
	}
	if !strings.Contains(run.output, "phase race . ok") {
		t.Errorf("the passing phase before it has no footer:\n%s", run.output)
	}
	if strings.Contains(run.output, "phase testhooks . ok") || strings.Contains(run.output, "every phase ok") {
		t.Errorf("the failing phase printed a footer:\n%s", run.output)
	}
	if !strings.Contains(run.output, "phase testhooks . failed with status 1") {
		t.Errorf("the failure is not named:\n%s", run.output)
	}
	if len(run.calls) != 2 {
		t.Errorf("%d calls after the failure, want none past it: %v", len(run.calls), run.calls)
	}
}

// R-TEST-9: a phase that fails once fails the run, though a second call would pass: nothing retries it.
func TestTestShPhasePassingOnASecondCallStillFails(t *testing.T) {
	checkout, environment := newTestShFixture(t)
	run := runTestSh(t, checkout, append(environment, "STUB_GO_FAIL_CALL=1"))
	if run.exitCode == 0 {
		t.Fatalf("a phase that failed once passed:\n%s", run.output)
	}
	if len(run.calls) != 1 {
		t.Errorf("the failing call was retried: %d calls %v", len(run.calls), run.calls)
	}
}

// An unknown cadence, or a gate without a milestone, is refused before anything runs.
func TestTestShRefusesAnUnknownCadence(t *testing.T) {
	checkout, environment := newTestShFixture(t)
	for _, arguments := range [][]string{{"--cadence", "weekly"}, {"--cadence", "gate"}, {"--gate", "M2"}, {"--fast"}} {
		run := runTestSh(t, checkout, environment, arguments...)
		if run.exitCode != 64 {
			t.Errorf("%v exited %d, want 64:\n%s", arguments, run.exitCode, run.output)
		}
		if len(run.calls) != 0 {
			t.Errorf("%v ran %v", arguments, run.calls)
		}
	}
}

// A gate's report must be whole: a phase that cannot run here fails a gate run, where merge goes on.
func TestTestShGateFailsOnAPhaseNotRun(t *testing.T) {
	checkout, environment := newTestShFixture(t)
	run := runTestSh(t, checkout, environment, "--cadence", "gate", "--gate", "M2")
	if run.exitCode != 1 {
		t.Fatalf("a gate with phases not run exited %d:\n%s", run.exitCode, run.output)
	}
	if !strings.Contains(run.output, "not run: t3-suites, t3, gate-report") {
		t.Errorf("the phases not run are not named:\n%s", run.output)
	}
	last := run.calls[len(run.calls)-1]
	if !strings.Contains(last[1], "-tags sidecar_tlc ./sidecartest/model") {
		t.Errorf("the gate's last call is %s, not the model step", last[1])
	}
}

// An interrupt takes the running phase down whole: a child the stub started holds a pipe open, and the
// pipe's end shows the child gone, with no sleep and no polling.
func TestTestShLeavesNoProcessBehind(t *testing.T) {
	checkout, environment := newTestShFixture(t)
	alive := filepath.Join(t.TempDir(), "alive")
	if err := syscall.Mkfifo(alive, 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("bash", filepath.Join(checkout, "test.sh"))
	command.Env = append(environment, "STUB_GO_HANG_CALL=1", "STUB_GO_ALIVE="+alive)
	command.Dir = checkout
	output := &strings.Builder{}
	command.Stdout = output
	command.Stderr = output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer command.Process.Kill()

	// the open returns once the stub's child holds the write end
	opened := make(chan *os.File, 1)
	go func() {
		file, err := os.OpenFile(alive, os.O_RDONLY, 0)
		if err != nil {
			opened <- nil
			return
		}
		opened <- file
	}()
	var reader *os.File
	select {
	case reader = <-opened:
	case <-time.After(testShGuardTimeout):
		t.Fatal("the stub's child never started")
	}
	if reader == nil {
		t.Fatal("opening the pipe failed")
	}
	defer reader.Close()

	if err := command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	ended := make(chan error, 1)
	go func() {
		_, err := io.Copy(io.Discard, bufio.NewReader(reader))
		ended <- err
	}()
	select {
	case err := <-ended:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(testShGuardTimeout):
		t.Fatal("the stub's child outlived the interrupted run")
	}
	exited := make(chan error, 1)
	go func() {
		exited <- command.Wait()
	}()
	select {
	case err := <-exited:
		exitError, ok := err.(*exec.ExitError)
		if !ok || exitError.ExitCode() != 143 {
			t.Errorf("an interrupted run ended with %v, want status 143:\n%s", err, output)
		}
	case <-time.After(testShGuardTimeout):
		t.Fatal("test.sh did not end after the interrupt")
	}
	if !strings.Contains(output.String(), "interrupted by TERM") {
		t.Errorf("the interrupt is not reported:\n%s", output)
	}
}

// On this tree, a dry run plans a race and a testhooks phase for each module the real Makefile lists,
// and runs nothing.
func TestTestShPlansEveryModuleOfThisTree(t *testing.T) {
	repository, err := thisCheckout()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("bash", filepath.Join(repository.moduleDirectory, "test.sh"), "--cadence", "nightly", "--dry-run")
	command.Dir = repository.moduleDirectory
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("%v:\n%s", err, output)
	}
	// the module list as make evaluates it, which is what test.sh reads
	listCommand := exec.Command("make", "-s", "--no-print-directory", "-f", "Makefile", "-f", "-", "test-sh-modules")
	listCommand.Dir = repository.moduleDirectory
	listCommand.Stdin = strings.NewReader("test-sh-modules:\n\t@echo $(modules)\n")
	modules, err := listCommand.Output()
	if err != nil {
		t.Fatal(err)
	}
	if len(strings.Fields(string(modules))) < 2 {
		t.Fatalf("the Makefile lists %q", modules)
	}
	for _, module := range strings.Fields(string(modules)) {
		for _, phase := range []string{"race " + module + ":", "testhooks " + module + ":"} {
			if !strings.Contains(string(output), "phase "+phase) {
				t.Errorf("no phase %q planned:\n%s", phase, output)
			}
		}
	}
	for _, phase := range []string{"phase leak:", "phase check:", "phase legs:", "phase stack:", "dry run, nothing ran"} {
		if !strings.Contains(string(output), phase) {
			t.Errorf("no %q planned:\n%s", phase, output)
		}
	}
}
