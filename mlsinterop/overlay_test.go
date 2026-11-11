//go:build !mlsinterop_tmc

// Runs §22.10's stacks row, tmc_test.go, under the one patch overlay/wire.go.patch records: tmc/mls's provisional
// 0x004F renumbered 0x0010, which no other tmc/mls suite uses, so both stacks sign and hash one suite number
// (plan-KEYS-interop-independence #1). The go command refuses -overlay for a file under GOMODCACHE, so the patch
// goes onto a temporary copy of the pinned module, which a temporary go.work puts in the build in its place; and a
// test cannot change its own build, so this test runs the stacks row in a second go test, under the tag that keeps
// tmc_test.go out of every other build, and fails when it does. The copy is of the module the proxy served and
// go.sum checked, and nothing else in it changes.
//
// The patch applies to tmc/mls's wire.go at the pinned version alone: its SHA-256 is checked before anything is
// patched, so a new pin fails here until the patch is read again against it (D-TEST-7).

package mlsinterop

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The pin, and wire.go's SHA-256 there.
const (
	tmcModulePath    = "github.com/tmc/mls"
	tmcModuleVersion = "v0.0.0-20260930074835-1c42a372504a"
	tmcWireSha256    = "0ece3d08383e79b61917ef78ef9c6f96fa535b4b3daf3d18a2832a781cf81e28"
)

// The one line the patch takes out and the one it puts in.
func tmcPatchLines(t *testing.T) (removed string, added string) {
	t.Helper()
	patch, err := os.ReadFile(filepath.Join("overlay", "wire.go.patch"))
	if err != nil {
		t.Fatal(err)
	}
	removedLines, addedLines := []string{}, []string{}
	scanner := bufio.NewScanner(bytes.NewReader(patch))
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "---"), strings.HasPrefix(line, "+++"), strings.HasPrefix(line, "@@"):
		case strings.HasPrefix(line, "-"):
			removedLines = append(removedLines, line[1:])
		case strings.HasPrefix(line, "+"):
			addedLines = append(addedLines, line[1:])
		default:
			t.Fatalf("overlay/wire.go.patch: a line %q that is no header, removal or addition", line)
		}
	}
	if len(removedLines) != 1 || len(addedLines) != 1 {
		t.Fatalf("overlay/wire.go.patch changes %d lines for %d, want one for one", len(removedLines), len(addedLines))
	}
	return removedLines[0], addedLines[0]
}

func TestTmcStacksUnderTheSuitePatch(t *testing.T) {
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("the stacks row needs the go command to build under its overlay: %v", err)
	}
	listed, err := exec.Command(goTool, "list", "-m", "-f", "{{.Dir}} {{.Version}}", tmcModulePath).Output()
	if err != nil {
		t.Fatalf("go list %s: %v", tmcModulePath, err)
	}
	directory, version, _ := strings.Cut(strings.TrimSpace(string(listed)), " ")
	if version != tmcModuleVersion {
		t.Fatalf("%s is at %s; the patch is read against %s", tmcModulePath, version, tmcModuleVersion)
	}
	upstream, err := os.ReadFile(filepath.Join(directory, "wire.go"))
	if err != nil {
		t.Fatal(err)
	}
	if digest := sha256.Sum256(upstream); hex.EncodeToString(digest[:]) != tmcWireSha256 {
		t.Fatalf("%s's wire.go has sha256 %x, not the one the patch was read against", tmcModulePath, digest)
	}
	removed, added := tmcPatchLines(t)
	if strings.Count(string(upstream), removed+"\n") != 1 {
		t.Fatalf("wire.go does not hold the patch's line exactly once")
	}
	if strings.Contains(string(upstream), "= 0x0010") {
		t.Fatalf("another tmc/mls suite already takes 0x0010")
	}
	patched := strings.Replace(string(upstream), removed+"\n", added+"\n", 1)

	// the pinned module, copied whole, its wire.go patched
	scratch := t.TempDir()
	copied := filepath.Join(scratch, "tmc")
	err = filepath.WalkDir(directory, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(directory, path)
		if err != nil {
			return err
		}
		target := filepath.Join(copied, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if relative == "wire.go" {
			data = []byte(patched)
		}
		return os.WriteFile(target, data, 0o644)
	})
	if err != nil {
		t.Fatalf("copying %s: %v", tmcModulePath, err)
	}
	moduleDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	workPath := filepath.Join(scratch, "go.work")
	work := "go 1.27.4\n\nuse (\n\t" + moduleDirectory + "\n\t" + copied + "\n)\n"
	if err := os.WriteFile(workPath, []byte(work), 0o644); err != nil {
		t.Fatal(err)
	}

	command := exec.Command(goTool, "test", "-count=1", "-tags", "mlsinterop_tmc", "-run", "^TestTmc", "-v", ".")
	command.Env = append(os.Environ(), "GOWORK="+workPath)
	output, err := command.CombinedOutput()
	t.Logf("go test -tags mlsinterop_tmc, tmc/mls's wire.go patched:\n%s", output)
	if err != nil {
		t.Fatalf("the stacks row failed: %v", err)
	}
	for _, name := range []string{"TestTmcSuiteIsPatched", "TestTmcLifecycleInBothDirections", "TestTmcReplaysTheInteropTranscripts"} {
		if !bytes.Contains(output, []byte("--- PASS: "+name)) {
			t.Errorf("%s did not pass under the overlay", name)
		}
	}
}
