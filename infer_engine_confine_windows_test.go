//go:build windows && !ios_extension && !sidecar_http

package sidecar

// The helper's confinement on Windows (infer_engine_confine_windows.go; INFER-M11-05): this test binary started as a
// helper the way the daemon starts ur-engine, in the AppContainer with read granted on its two directories, checks its
// token, proves the state directory unlistable and tries what a hostile model file would, reporting what Windows
// answered. These are compiled on the windows leg and run by hand on a Windows host (External: no Windows host here).

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// What makes this test binary a confined helper's probe rather than the tests.
const testInferEngineWindowsProbeVariable = "UR_TEST_INFER_ENGINE_WINDOWS_PROBE"

func init() {
	if os.Getenv(testInferEngineWindowsProbeVariable) != "" {
		os.Exit(testInferEngineWindowsProbe())
	}
}

// What the probe saw: whether each attempt succeeded, and the confinement's refusal if any.
type testInferEngineWindowsReport struct {
	ConfineError string `json:"confine_error,omitempty"`
	ListState    bool   `json:"list_state"`
	ReadOutside  bool   `json:"read_outside"`
	ReadModel    bool   `json:"read_model"`
	WriteModels  bool   `json:"write_models"`
	DialLoopback bool   `json:"dial_loopback"`
}

// The probe: confines itself from its environment, then tries each thing and prints the report.
func testInferEngineWindowsProbe() int {
	report := &testInferEngineWindowsReport{}
	confinement, err := parseInferEngineConfineEnvironment(os.Environ())
	if err == nil {
		err = inferEngineConfine(confinement, DefaultInferSettings(), os.Args, os.Environ())
	}
	if err != nil {
		report.ConfineError = err.Error()
		json.NewEncoder(os.Stdout).Encode(report)
		return 1
	}
	_, err = os.ReadDir(confinement.DeniedDirectory)
	report.ListState = err == nil
	_, err = os.ReadFile(filepath.Join(confinement.DeniedDirectory, "outside"))
	report.ReadOutside = err == nil
	_, err = os.ReadFile(filepath.Join(confinement.ModelDirectory, "model"))
	report.ReadModel = err == nil
	report.WriteModels = os.WriteFile(filepath.Join(confinement.ModelDirectory, "written"), []byte("x"), 0o600) == nil
	connection, err := net.DialTimeout("tcp", "127.0.0.1:9", time.Second)
	if err == nil {
		connection.Close()
	}
	report.DialLoopback = err == nil
	json.NewEncoder(os.Stdout).Encode(report)
	return 0
}

// Started as the daemon starts a helper, the probe runs in its AppContainer: the state directory and a file in it do
// not read, nothing in the models is writable, no connection opens, and its model reads.
func TestEngineConfinedWindowsAppContainer(t *testing.T) {
	if err := inferEngineConfineAvailable(); err != nil {
		t.Skipf("this Windows makes no AppContainer: %s", err)
	}
	confinement := testInferEngineConfinement(t)
	for path, content := range map[string]string{
		filepath.Join(confinement.DeniedDirectory, "outside"): "the state's own",
		filepath.Join(confinement.ModelDirectory, "model"):    "model weights",
	} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	stderr := &bytes.Buffer{}
	child, err := inferEngineStartChild(&inferEngineChildSpec{
		Path:        executable,
		Args:        []string{"-test.run=^$"},
		Env:         []string{testInferEngineWindowsProbeVariable + "=1"},
		Directory:   confinement.EngineDirectory,
		Stderr:      stderr,
		Confinement: confinement,
	})
	if err != nil {
		t.Fatal(err)
	}
	child.stdin.Close()
	output := &bytes.Buffer{}
	if _, err := output.ReadFrom(child.stdout); err != nil {
		t.Fatal(err)
	}
	waitErr := child.wait()
	report := &testInferEngineWindowsReport{}
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), report); err != nil {
		t.Fatalf("the probe reported %q (stderr %q, wait %v): %v", output.String(), stderr.String(), waitErr, err)
	}
	if report.ConfineError != "" || waitErr != nil {
		t.Fatalf("the probe did not confine itself: %s (%v)", report.ConfineError, waitErr)
	}
	if report.ListState || report.ReadOutside || report.WriteModels || report.DialLoopback {
		t.Errorf("the AppContainer let through: %+v", report)
	}
	if !report.ReadModel {
		t.Error("the model did not read in the AppContainer")
	}
}

// This test process runs in no AppContainer, so as a helper it refuses to run.
func TestEngineConfinedWindowsRefusesOutsideAppContainer(t *testing.T) {
	confinement := testInferEngineConfinement(t)
	if err := inferEngineConfine(confinement, DefaultInferSettings(), os.Args, os.Environ()); !errors.Is(err, ErrInferEngineUnconfined) {
		t.Errorf("a helper outside an AppContainer would run: %v", err)
	}
}
