//go:build !js && !ios && !android

// Holds testdata/signed/ byte-equal on §4.7's sidecar_http leg, the page Worker's, which go test on the host never
// reaches: that leg's crypto is Go's generic code, where the host's is assembly, so the same vectors are a real
// comparison. go_js_wasm_exec gives these tests the file system they read the vectors from, which the root's Worker
// harness (legs_test.go) leaves out on purpose. This needs go and node, so a mobile leg's test binary, which has
// neither, leaves it out.

package bridge

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The vectors, the countersign rules and both fuzz targets' seeds, run on the leg itself.
func TestSignedVectorsHoldOnTheHttpLeg(t *testing.T) {
	// a failure and not a skip: a leg that did not run has not passed
	if _, err := exec.LookPath("node"); err != nil {
		t.Fatalf("the sidecar_http leg runs in node: %v", err)
	}
	goroot, err := exec.Command("go", "env", "GOROOT").Output()
	if err != nil {
		t.Fatal(err)
	}
	wasmExec := filepath.Join(strings.TrimSpace(string(goroot)), "lib", "wasm", "go_js_wasm_exec")
	tests := "^(TestSignedVectors|TestPresenceAct|TestSignedBytes|TestVerifyPresenceCountersign|" +
		"FuzzSignedTypeConfusion|FuzzVerifyPresenceCountersign)"
	command := exec.Command("go", "test", "-count=1", "-v", "-tags", "sidecar_http", "-exec", wasmExec, "-run", tests, ".")
	command.Env = append(os.Environ(), "GOOS=js", "GOARCH=wasm")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("the leg's tests failed: %v\n%s", err, output)
	}
	// each by name, since a run that matched nothing would still exit 0
	for _, name := range []string{
		"TestSignedVectorsAreByteEqual",
		"TestSignedVectorsVerify",
		"TestSignedVectorsWalk",
		"TestVerifyPresenceCountersignFiveStatementAct",
		"FuzzSignedTypeConfusion",
		"FuzzVerifyPresenceCountersign",
	} {
		if !strings.Contains(string(output), "--- PASS: "+name+" ") {
			t.Errorf("%s did not pass\n%s", name, output)
		}
	}
}
