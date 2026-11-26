//go:build linux && !android && !ios_extension && !sidecar_http

package sidecar

// The helper's confinement on Linux (infer_engine_confine_linux.go; INFER-M11-05), on a kernel with Landlock: this
// test binary started as a helper confines itself as ur-engine does, its first stage exec'ing it again confined, and
// then tries what a hostile model file would, reporting what the kernel answered: a socket of every family refused,
// the state directory and a file outside unreadable, nothing writable in the directories it reads, its model readable.
// A kernel without Landlock skips them, and TestEngineConfineNoLandlockRefuses holds the refusal there.

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// What makes this test binary a confined helper's probe rather than the tests.
const testInferEngineConfineProbeVariable = "UR_TEST_INFER_ENGINE_CONFINE_PROBE"

func init() {
	if os.Getenv(testInferEngineConfineProbeVariable) != "" {
		os.Exit(testInferEngineConfineProbe())
	}
}

// What the probe saw: each attempt's errno, 0 for success.
type testInferEngineConfineReport struct {
	SocketInet   int    `json:"socket_inet"`
	SocketInet6  int    `json:"socket_inet6"`
	SocketUnix   int    `json:"socket_unix"`
	SocketPair   int    `json:"socket_pair"`
	ListState    int    `json:"list_state"`
	ReadOutside  int    `json:"read_outside"`
	ReadModel    int    `json:"read_model"`
	WriteModels  int    `json:"write_models"`
	WriteEngine  int    `json:"write_engine"`
	RemoveModel  int    `json:"remove_model"`
	ExecOutside  int    `json:"exec_outside"`
	NoNewPrivs   int    `json:"no_new_privs"`
	SeccompMode  int    `json:"seccomp_mode"`
	ConfineError string `json:"confine_error,omitempty"`
}

// The errno err holds, 0 for none, -1 for an error with no errno.
func testInferEngineErrno(err error) int {
	if err == nil {
		return 0
	}
	var errno unix.Errno
	if errors.As(err, &errno) {
		return int(errno)
	}
	return -1
}

// The probe: confines itself from its environment, then tries each thing and prints the report. Exits 0 once it
// reported, 1 where it could not confine itself.
func testInferEngineConfineProbe() int {
	report := &testInferEngineConfineReport{}
	confinement, err := parseInferEngineConfineEnvironment(os.Environ())
	if err == nil {
		err = inferEngineConfine(confinement, DefaultInferSettings(), os.Args, os.Environ())
	}
	if err != nil {
		report.ConfineError = err.Error()
		json.NewEncoder(os.Stdout).Encode(report)
		return 1
	}
	socket := func(family int, kind int) int {
		fd, err := unix.Socket(family, kind|unix.SOCK_CLOEXEC, 0)
		if err == nil {
			unix.Close(fd)
		}
		return testInferEngineErrno(err)
	}
	report.SocketInet = socket(unix.AF_INET, unix.SOCK_STREAM)
	report.SocketInet6 = socket(unix.AF_INET6, unix.SOCK_DGRAM)
	report.SocketUnix = socket(unix.AF_UNIX, unix.SOCK_STREAM)
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err == nil {
		unix.Close(fds[0])
		unix.Close(fds[1])
	}
	report.SocketPair = testInferEngineErrno(err)
	_, err = os.ReadDir(confinement.DeniedDirectory)
	report.ListState = testInferEngineErrno(err)
	_, err = os.ReadFile(filepath.Join(confinement.DeniedDirectory, "outside"))
	report.ReadOutside = testInferEngineErrno(err)
	_, err = os.ReadFile(filepath.Join(confinement.ModelDirectory, "model"))
	report.ReadModel = testInferEngineErrno(err)
	report.WriteModels = testInferEngineErrno(os.WriteFile(filepath.Join(confinement.ModelDirectory, "written"), []byte("x"), 0o600))
	file, err := os.OpenFile(filepath.Join(confinement.EngineDirectory, "library"), os.O_WRONLY, 0)
	if err == nil {
		file.Close()
	}
	report.WriteEngine = testInferEngineErrno(err)
	report.RemoveModel = testInferEngineErrno(os.Remove(filepath.Join(confinement.ModelDirectory, "model")))
	err = unix.Exec(filepath.Join(confinement.DeniedDirectory, "program"), []string{"program"}, nil)
	report.ExecOutside = testInferEngineErrno(err)
	noNewPrivs, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
	if err != nil {
		noNewPrivs = -1
	}
	report.NoNewPrivs = noNewPrivs
	mode, err := unix.PrctlRetInt(unix.PR_GET_SECCOMP, 0, 0, 0, 0)
	if err != nil {
		mode = -1
	}
	report.SeccompMode = mode
	json.NewEncoder(os.Stdout).Encode(report)
	return 0
}

// Runs this test binary as a confined helper over a fresh state directory, its engine and model directories inside,
// and reads its report; skips where the kernel offers no Landlock.
func testInferEngineRunConfined(t *testing.T) (*testInferEngineConfineReport, int) {
	t.Helper()
	if err := inferEngineConfineAvailable(); err != nil {
		t.Skipf("this kernel cannot confine a helper: %s", err)
	}
	confinement := testInferEngineConfinement(t)
	for path, content := range map[string]string{
		filepath.Join(confinement.DeniedDirectory, "outside"): "the state's own",
		filepath.Join(confinement.DeniedDirectory, "program"): "#!/bin/sh\nexit 0\n",
		filepath.Join(confinement.ModelDirectory, "model"):    "model weights",
		filepath.Join(confinement.EngineDirectory, "library"): "engine library",
	} {
		if err := os.WriteFile(path, []byte(content), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	command := exec.Command(os.Args[0], "-test.run=^$")
	command.Env = append([]string{testInferEngineConfineProbeVariable + "=1"}, inferEngineConfineEnvironment(confinement)...)
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	command.Stdout = stdout
	command.Stderr = stderr
	err := command.Run()
	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatal(err)
		}
		exitCode = exitErr.ExitCode()
	}
	report := &testInferEngineConfineReport{}
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), report); err != nil {
		t.Fatalf("the probe reported %q (stderr %q): %v", stdout.String(), stderr.String(), err)
	}
	if report.ConfineError != "" || exitCode != 0 {
		t.Fatalf("the probe did not confine itself (exit %d): %s", exitCode, report.ConfineError)
	}
	// nothing it tried left a mark
	if _, err := os.Stat(filepath.Join(confinement.ModelDirectory, "written")); err == nil {
		t.Error("the confined helper wrote into the model directory")
	}
	if _, err := os.Stat(filepath.Join(confinement.ModelDirectory, "model")); err != nil {
		t.Error("the confined helper removed its model")
	}
	return report, exitCode
}

// Every socket is refused, the network's and the local ones alike, since the daemon's own control socket is a unix
// socket: the filter answers EACCES before any address is named.
func TestEngineConfinedLinuxRefusesSocket(t *testing.T) {
	report, _ := testInferEngineRunConfined(t)
	eacces := int(unix.EACCES)
	if report.SocketInet != eacces || report.SocketInet6 != eacces || report.SocketUnix != eacces || report.SocketPair != eacces {
		t.Errorf("sockets: %+v", report)
	}
	if report.NoNewPrivs != 1 || report.SeccompMode != unix.SECCOMP_MODE_FILTER {
		t.Errorf("no_new_privs %d, seccomp mode %d", report.NoNewPrivs, report.SeccompMode)
	}
}

// The state directory and what it holds outside the two directories are unreadable, nothing in those two is writable
// or removable, nothing outside executes, and the model reads.
func TestEngineConfinedLinuxRefusesReadOutside(t *testing.T) {
	report, _ := testInferEngineRunConfined(t)
	eacces := int(unix.EACCES)
	refused := map[string]int{
		"list the state directory":        report.ListState,
		"read a file outside":             report.ReadOutside,
		"write into the models":           report.WriteModels,
		"open the engine's file to write": report.WriteEngine,
		"remove the model":                report.RemoveModel,
		"exec a program outside":          report.ExecOutside,
	}
	for what, errno := range refused {
		if errno != eacces {
			t.Errorf("%s: errno %d, want EACCES", what, errno)
		}
	}
	if report.ReadModel != 0 {
		t.Errorf("the model did not read: errno %d", report.ReadModel)
	}
}

// A kernel with no Landlock: the helper refuses before it confines or execs anything, and the daemon lists local
// inference unavailable with that reason rather than run a helper unconfined.
func TestEngineConfineNoLandlockRefuses(t *testing.T) {
	probe := inferEngineLandlockAbi
	t.Cleanup(func() { inferEngineLandlockAbi = probe })
	inferEngineLandlockAbi = func() (int, error) {
		return 0, unix.ENOSYS
	}
	confinement := testInferEngineConfinement(t)
	err := inferEngineConfine(confinement, DefaultInferSettings(), os.Args, os.Environ())
	if !errors.Is(err, ErrInferEngineUnconfined) || !strings.Contains(err.Error(), "Landlock") {
		t.Errorf("a helper with no Landlock: %v", err)
	}
	if err := inferEngineConfineAvailable(); !errors.Is(err, ErrInferEngineUnconfined) {
		t.Errorf("the daemon would start a helper: %v", err)
	}
	process, err := NewInferEngineProcess(&InferEngineProcessArgs{
		HelperPath:      os.Args[0],
		EngineDirectory: confinement.EngineDirectory,
		ModelDirectory:  confinement.ModelDirectory,
		StateDirectory:  confinement.DeniedDirectory,
		Manifest:        &InferManifest{Version: inferManifestVersion},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer process.Close()
	if _, err := process.Capabilities(t.Context()); err == nil || !strings.Contains(err.Error(), "Landlock") {
		t.Errorf("the daemon's capabilities with no Landlock: %v", err)
	}
	// a kernel that answers a version below 1 is refused alike
	inferEngineLandlockAbi = func() (int, error) {
		return 0, nil
	}
	if err := inferEngineConfine(confinement, DefaultInferSettings(), os.Args, os.Environ()); !errors.Is(err, ErrInferEngineUnconfined) {
		t.Errorf("a version-0 Landlock: %v", err)
	}
	// the second stage proves what the kernel holds, so a marker alone confines nothing: this test process has
	// neither no_new_privs nor a filter
	marked := append(os.Environ(), inferEngineConfinedEnvironment)
	if err := inferEngineConfine(confinement, DefaultInferSettings(), os.Args, marked); !errors.Is(err, ErrInferEngineUnconfined) {
		t.Errorf("a marker alone passed: %v", err)
	}
}
