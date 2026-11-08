//go:build sidecar_check

// §22.7's list is generated: metadata_list.yml is §2.8's fenced block, byte for byte, comments
// included, so a row changes in the design and reaches the repository through make metadata. A hand
// edit here, or a design change that skipped make metadata, fails. sidecartest's strict reader reads
// the same bytes in go test ./..., and this package imports nothing of ours, so this reads only bytes.

package check

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The list moves with the root module on a release branch, so it is relative to the module. design/
// stays at the repository's top, beside that module (§4.9), so the section is relative to the top.
const (
	metadataListFileName    = "metadata_list.yml"
	metadataListSectionPath = "design/source/sections/02-TRUST.md"
)

// What opens the block in §2.8, and what closes it.
const (
	metadataListHeading = "**The list**"
	metadataFenceOpen   = "```yaml"
	metadataFenceClose  = "```"
)

// The fenced block after §2.8's heading, without its fence lines, each line with its newline.
func metadataListBlock(section []byte) ([]byte, bool) {
	block := bytes.Buffer{}
	headingSeen := false
	fenceOpen := false
	for _, line := range bytes.SplitAfter(section, []byte("\n")) {
		text := strings.TrimSuffix(string(line), "\n")
		switch {
		case fenceOpen && text == metadataFenceClose:
			return block.Bytes(), true
		case fenceOpen:
			block.Write(line)
		case headingSeen && text == metadataFenceOpen:
			fenceOpen = true
		case strings.HasPrefix(text, metadataListHeading):
			headingSeen = true
		}
	}
	return nil, false
}

// The first line two texts differ on, numbered from 1, for a finding a reader can act on.
func firstDifferentLine(a []byte, b []byte) int {
	aLines := bytes.Split(a, []byte("\n"))
	bLines := bytes.Split(b, []byte("\n"))
	for index := 0; index < len(aLines) && index < len(bLines); index += 1 {
		if !bytes.Equal(aLines[index], bLines[index]) {
			return index + 1
		}
	}
	return 1 + min(len(aLines), len(bLines))
}

// Whether the list in moduleDirectory is the block of §2.8 in topDirectory. The two are one directory
// in development and differ on a release branch.
func metadataListFindings(topDirectory string, moduleDirectory string) []string {
	section, err := os.ReadFile(filepath.Join(topDirectory, metadataListSectionPath))
	if err != nil {
		return []string{findingf("reading §2.8: %v", err)}
	}
	block, found := metadataListBlock(section)
	if !found {
		return []string{findingf("%s holds no fenced block under %s", metadataListSectionPath, metadataListHeading)}
	}
	list, err := os.ReadFile(filepath.Join(moduleDirectory, metadataListFileName))
	if err != nil {
		return []string{findingf("reading the list: %v; make metadata writes it", err)}
	}
	if !bytes.Equal(list, block) {
		return []string{findingf("%s differs from §2.8's block at line %d: a row changes in the design, and make metadata brings it here", metadataListFileName, firstDifferentLine(list, block))}
	}
	return nil
}

func TestMetadataListIsSection2sBlock(t *testing.T) {
	repository := openThisCheckout(t)
	failFindings(t, "metadata list", metadataListFindings(repository.topDirectory, repository.moduleDirectory))
}

// A module directory holding what make metadata reads, and a list it would write.
func plantMetadataList(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.MkdirAll(filepath.Join(directory, filepath.Dir(metadataListSectionPath)), 0o700); err != nil {
		t.Fatal(err)
	}
	section := "### 2.8\n\n```yaml\nnot: this block\n```\n\n**The list** (the only TTL table):\n\n```yaml\n# metadata_list.yml v1\nevs-1:\n  withdrawn: gone\n```\n\nAfter it.\n"
	if err := os.WriteFile(filepath.Join(directory, metadataListSectionPath), []byte(section), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, metadataListFileName), []byte("# metadata_list.yml v1\nevs-1:\n  withdrawn: gone\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return directory
}

func TestMetadataListPassesTheBlockItself(t *testing.T) {
	directory := plantMetadataList(t)
	failFindings(t, "metadata list", metadataListFindings(directory, directory))
}

// A release branch's shape: the section at the top, and the list one directory down in v2026/.
func TestMetadataListReadsTheSectionBesideAReleaseModule(t *testing.T) {
	topDirectory := plantMetadataList(t)
	moduleDirectory := filepath.Join(topDirectory, "v2026")
	if err := os.Mkdir(moduleDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(topDirectory, metadataListFileName), filepath.Join(moduleDirectory, metadataListFileName)); err != nil {
		t.Fatal(err)
	}
	failFindings(t, "metadata list", metadataListFindings(topDirectory, moduleDirectory))
	wantFindings(t, metadataListFindings(moduleDirectory, moduleDirectory), "reading §2.8")
}

func TestMetadataListRefusesAHandEdit(t *testing.T) {
	directory := plantMetadataList(t)
	if err := os.WriteFile(filepath.Join(directory, metadataListFileName), []byte("# metadata_list.yml v1\nevs-1:\n  withdrawn: edited\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	wantFindings(t, metadataListFindings(directory, directory), "differs from §2.8's block at line 3")
}

func TestMetadataListRefusesAnEditedComment(t *testing.T) {
	directory := plantMetadataList(t)
	if err := os.WriteFile(filepath.Join(directory, metadataListFileName), []byte("# metadata_list.yml v2\nevs-1:\n  withdrawn: gone\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	wantFindings(t, metadataListFindings(directory, directory), "differs from §2.8's block at line 1")
}

func TestMetadataListRefusesAMissingList(t *testing.T) {
	directory := plantMetadataList(t)
	if err := os.Remove(filepath.Join(directory, metadataListFileName)); err != nil {
		t.Fatal(err)
	}
	wantFindings(t, metadataListFindings(directory, directory), "make metadata writes it")
}

func TestMetadataListRefusesASectionWithNoBlock(t *testing.T) {
	directory := plantMetadataList(t)
	if err := os.WriteFile(filepath.Join(directory, metadataListSectionPath), []byte("### 2.8\n\nNo list here.\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	wantFindings(t, metadataListFindings(directory, directory), "holds no fenced block")
}

// A block §2.8 opened and never closed is no block.
func TestMetadataListRefusesAnUnclosedBlock(t *testing.T) {
	directory := plantMetadataList(t)
	if err := os.WriteFile(filepath.Join(directory, metadataListSectionPath), []byte("**The list**\n\n```yaml\nevs-1:\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	wantFindings(t, metadataListFindings(directory, directory), "holds no fenced block")
}

// The real Makefile on a planted section, so make metadata and this rule are shown to read one block.
func runMakeMetadata(t *testing.T, directory string) error {
	t.Helper()
	makefile, err := os.ReadFile(filepath.Join(openThisCheckout(t).moduleDirectory, "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "Makefile"), makefile, 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("make", "metadata")
	command.Dir = directory
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("%w\n%s", err, output)
	}
	return nil
}

func TestMakeMetadataRestoresAHandEdit(t *testing.T) {
	directory := plantMetadataList(t)
	if err := os.WriteFile(filepath.Join(directory, metadataListFileName), []byte("edited\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runMakeMetadata(t, directory); err != nil {
		t.Fatal(err)
	}
	failFindings(t, "metadata list", metadataListFindings(directory, directory))
}

// With no block to copy it fails, and an empty list never replaces a real one.
func TestMakeMetadataKeepsTheListWithoutABlock(t *testing.T) {
	directory := plantMetadataList(t)
	if err := os.WriteFile(filepath.Join(directory, metadataListSectionPath), []byte("### 2.8\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runMakeMetadata(t, directory); err == nil {
		t.Errorf("make metadata succeeded with nothing to copy")
	}
	list, err := os.ReadFile(filepath.Join(directory, metadataListFileName))
	if err != nil {
		t.Fatal(err)
	}
	if len(list) == 0 {
		t.Errorf("make metadata emptied the list")
	}
}
