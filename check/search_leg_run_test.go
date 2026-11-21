//go:build sidecar_check

// The forwarding leg's own tests, run (QD-988; §18.10, §22.5's §18 row): the root's rpc_search_leg_test.go, which shows
// the leg refusing SEARCH both ways and linking neither search.proto's nor evsindex.proto's descriptor. The root's
// other tests are written for the legs that run them and name code the ios_extension tag leaves out, so the root's
// test package does not build under the tag. This compiles it with every other test file replaced by an empty one
// through -overlay, on the host's GOOS with the extension bind's tags, which select the same root and protocol files
// as the leg's slices but for the platform's own.

package check

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The root's test file that only the ios_extension legs' tag selects, and the tests it must run.
const iosExtensionLegTestFile = "rpc_search_leg_test.go"

var iosExtensionLegTestNames = []string{
	"TestSearchLegCallRefusesSearch", "TestSearchLegHandleRefusesSearch", "TestSearchLegLinksNoSearchDescriptor",
	"TestSearchLegTakesNoSearchResult",
}

// A test go test -v reports passed.
var legTestPassPattern = regexp.MustCompile(`(?m)^--- PASS: (\w+) `)

// Runs testFile's tests in the root module under tags, every other test file of the root package left out, and
// answers the tests that passed. A run that fails is an error carrying the go command's account.
func (self *repository) runRootLegTests(t testing.TB, tags []string, testFile string) ([]string, error) {
	t.Helper()
	environment := goEnvironment()
	output, err := runGo(self.moduleDirectory, environment, "list", "-tags="+strings.Join(tags, ","), "-json=Name,Dir,TestGoFiles,XTestGoFiles", ".")
	if err != nil {
		return nil, err
	}
	listed := &struct {
		Name         string
		Dir          string
		TestGoFiles  []string
		XTestGoFiles []string
	}{}
	if err := json.Unmarshal(output, listed); err != nil {
		return nil, err
	}
	if !slices.Contains(listed.TestGoFiles, testFile) {
		return nil, fmt.Errorf("-tags=%s selects no %s among the root's test files, so no test of it ran", strings.Join(tags, ","), testFile)
	}
	scratch := t.TempDir()
	replace := map[string]string{}
	stub := func(packageName string, testFiles []string) error {
		stubPath := filepath.Join(scratch, packageName+".go")
		if err := os.WriteFile(stubPath, []byte("package "+packageName+"\n"), 0o600); err != nil {
			return err
		}
		for _, name := range testFiles {
			if name != testFile {
				replace[filepath.Join(listed.Dir, name)] = stubPath
			}
		}
		return nil
	}
	if err := stub(listed.Name, listed.TestGoFiles); err != nil {
		return nil, err
	}
	if err := stub(listed.Name+"_test", listed.XTestGoFiles); err != nil {
		return nil, err
	}
	data, err := json.Marshal(map[string]map[string]string{"Replace": replace})
	if err != nil {
		return nil, err
	}
	overlayPath := filepath.Join(scratch, "overlay.json")
	if err := os.WriteFile(overlayPath, data, 0o600); err != nil {
		return nil, err
	}
	// a failed test's account is on stdout, which runGo keeps out of its error
	command := exec.Command("go", "test", "-count=1", "-v", "-overlay="+overlayPath, "-tags="+strings.Join(tags, ","), ".")
	command.Dir = self.moduleDirectory
	command.Env = environment
	output, err = command.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("go test of %s under -tags=%s: %w\n%s", testFile, strings.Join(tags, ","), err, output)
	}
	passed := []string{}
	for _, match := range legTestPassPattern.FindAllStringSubmatch(string(output), -1) {
		passed = append(passed, match[1])
	}
	slices.Sort(passed)
	return passed, nil
}

// The leg refuses SEARCH and links no search descriptor: every test of rpc_search_leg_test.go runs and passes under
// the extension bind's tags. A test that did not run fails this as one that failed does.
func TestLegsRunTheIosExtensionLegsSearchTests(t *testing.T) {
	repository := openThisCheckout(t)
	passed, err := repository.runRootLegTests(t, []string{mobileBindTag, iosExtensionTag}, iosExtensionLegTestFile)
	if err != nil {
		t.Fatalf("the ios_extension legs' tests of SEARCH did not pass: %v", err)
	}
	if !slices.Equal(passed, iosExtensionLegTestNames) {
		t.Errorf("the ios_extension legs' tests that passed are %v, want %v", passed, iosExtensionLegTestNames)
	}
}

// Runs the forwarding role's shared call sites with the host stores and signers absent.
func TestIosExtensionLegsRefuseSidecarOperations(t *testing.T) {
	repository := openThisCheckout(t)
	passed, err := repository.runRootLegTests(t, []string{mobileBindTag, iosExtensionTag}, "sidecar_role_extension_test.go")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"TestForwardingLegKeepsTheSidecarUnenrolled",
		"TestForwardingLegReadsWithoutSearchOrWriteRecovery",
		"TestForwardingLegRefusesRecordAndPeerStreamStores",
	}
	if !slices.Equal(passed, want) {
		t.Errorf("forwarding role tests passed %v, want %v", passed, want)
	}
}

// Its control: without the extension's tag the file is not the build's, so the run reads no test and says so, never
// passing on nothing.
func TestLegsRunNoIosExtensionLegTestWithoutTheTag(t *testing.T) {
	repository := openThisCheckout(t)
	if passed, err := repository.runRootLegTests(t, []string{mobileBindTag}, iosExtensionLegTestFile); err == nil {
		t.Errorf("a run without the tag passed %v", passed)
	}
}
