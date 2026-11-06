//go:build !js

// Proves §4.4's build rule: the sidecar_http js leg links no connect or gVisor package, every file
// that names one carries !sidecar_http, and every host_ file does whether it names one or not. These
// run on the host, where go and the source tree are, and read the leg through an explicit go/build
// context or `go list`, which -tags does not reach.

package sidecar

import (
	"go/build"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func sidecarHttpBuildContext() build.Context {
	buildContext := build.Default
	buildContext.GOOS = "js"
	buildContext.GOARCH = "wasm"
	buildContext.CgoEnabled = false
	buildContext.BuildTags = []string{"sidecar_http"}
	return buildContext
}

func rootGoFiles(t *testing.T) []string {
	t.Helper()
	goFiles, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	if len(goFiles) == 0 {
		t.Fatal("no go files")
	}
	return goFiles
}

func namesConnect(importPath string) bool {
	return importPath == "github.com/urnetwork/connect" ||
		strings.HasPrefix(importPath, "github.com/urnetwork/connect/") ||
		strings.HasPrefix(importPath, "gvisor.dev/")
}

func TestEveryHostFileIsOffTheHttpLeg(t *testing.T) {
	buildContext := sidecarHttpBuildContext()
	hostFileCount := 0
	for _, goFile := range rootGoFiles(t) {
		if !strings.HasPrefix(goFile, "host_") {
			continue
		}
		hostFileCount += 1
		matched, err := buildContext.MatchFile(".", goFile)
		if err != nil {
			t.Fatal(err)
		}
		if matched {
			t.Errorf("%s builds on the sidecar_http leg", goFile)
		}
	}
	if hostFileCount == 0 {
		t.Error("no host_ files")
	}
}

func TestOnlyFilesOffTheHttpLegNameConnect(t *testing.T) {
	buildContext := sidecarHttpBuildContext()
	fileSet := token.NewFileSet()
	for _, goFile := range rootGoFiles(t) {
		file, err := parser.ParseFile(fileSet, goFile, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		matched, err := buildContext.MatchFile(".", goFile)
		if err != nil {
			t.Fatal(err)
		}
		for _, importSpec := range file.Imports {
			importPath, err := strconv.Unquote(importSpec.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			if matched && namesConnect(importPath) {
				t.Errorf("%s imports %s on the sidecar_http leg", goFile, importPath)
			}
		}
	}
}

// A blank import to hold the require must not outlive the first real one: connect_require.go's comment
// has it deleted in that change, and a second one would keep connect in go.mod by accident.
func TestConnectRequireHolderIsGone(t *testing.T) {
	if _, err := os.Stat("connect_require.go"); !os.IsNotExist(err) {
		t.Errorf("connect_require.go: %v", err)
	}
}

func goListDeps(t *testing.T, env []string, args ...string) []string {
	t.Helper()
	command := exec.Command("go", append([]string{"list", "-deps"}, args...)...)
	command.Env = append(os.Environ(), env...)
	output, err := command.Output()
	if err != nil {
		stderr := ""
		if exitError, ok := err.(*exec.ExitError); ok {
			stderr = string(exitError.Stderr)
		}
		t.Fatalf("go list: %v\n%s", err, stderr)
	}
	return strings.Fields(string(output))
}

// What `make check` will enforce from M1 (§4.7), on the whole transitive graph.
func TestHttpLegLinksNoConnectOrGvisor(t *testing.T) {
	deps := goListDeps(t, []string{"GOOS=js", "GOARCH=wasm"}, "-tags", "sidecar_http", ".")
	if !slices.Contains(deps, "github.com/urnetwork/sidecar") {
		t.Fatalf("deps %v", deps)
	}
	for _, dep := range deps {
		if namesConnect(dep) {
			t.Errorf("the sidecar_http leg links %s", dep)
		}
	}
}

// §4.5: engines never import server, so its libraries stay out of this module.
func TestRootLinksNoHostLibrary(t *testing.T) {
	deps := goListDeps(t, nil, ".")
	if !slices.Contains(deps, "github.com/urnetwork/connect") {
		t.Fatalf("the connect leg links no connect: %v", deps)
	}
	for _, dep := range deps {
		for _, refused := range []string{
			"github.com/urnetwork/server",
			"github.com/urnetwork/sdk",
			"github.com/redis/go-redis",
			"github.com/minio/minio-go",
			"github.com/prometheus/client_golang",
		} {
			if dep == refused || strings.HasPrefix(dep, refused+"/") {
				t.Errorf("the root links %s", dep)
			}
		}
	}
}
