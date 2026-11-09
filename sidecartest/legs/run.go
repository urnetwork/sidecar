// Runs the legs: for each, lists the packages with tests under the leg's build, compiles each one's test
// binary with go test -c, and runs every binary on the leg's runner with -test.count=1. A leg's
// outcome is pass only when every binary ran and passed.

package legs

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// What a leg came to. Only pass counts.
type Outcome string

const (
	OutcomePass     Outcome = "pass"
	OutcomeFail     Outcome = "fail"
	OutcomeCompiled Outcome = "compiled"
	OutcomeNotRun   Outcome = "not run"
)

// One package's binary on a leg.
type PackageResult struct {
	ImportPath string
	Outcome    Outcome
	// the binary's output, or the compiler's
	Output string
}

// One leg's report.
type Result struct {
	Leg      *Leg
	Outcome  Outcome
	Why      string
	Packages []*PackageResult
}

// The leg's line for a report: "tests js/wasm: fail (2 of 14 packages failed)".
func (self *Result) String() string {
	text := self.Leg.Name + ": " + string(self.Outcome)
	if self.Why != "" {
		text += " (" + self.Why + ")"
	}
	return text
}

// Where and how legs run.
type RunSettings struct {
	// the repository's top, holding the root module and the nested ones
	Directory string
	// the go command
	Go string
	// node, for the js/wasm legs; empty looks it up on PATH
	Node string
	// docker, for the container legs; empty looks it up on PATH
	Docker string
	// the linux image a container leg runs its binaries in. A static test binary needs only a shell
	// and /tmp; an image this host lacks leaves the leg not run, since nothing here fetches one.
	ContainerImage string
	// passed to each binary as -test.run; empty runs every test
	RunPattern string
	// extra environment for each binary, as KEY=value
	Environment []string
	// how many packages of a leg compile at once. Non-positive means one at a time.
	CompileConcurrency int
	// a bound on one binary's run, as -test.timeout
	TestTimeout time.Duration
}

// The go command on PATH, the sidecar-test-legs image, four compiles at once, 30 minutes a binary.
func DefaultRunSettings(directory string) *RunSettings {
	return &RunSettings{
		Directory:          directory,
		Go:                 "go",
		ContainerImage:     "sidecar-test-legs",
		CompileConcurrency: 4,
		TestTimeout:        30 * time.Minute,
	}
}

// Runs each leg in turn and reports each, in order.
func Run(ctx context.Context, settings *RunSettings, legs []*Leg) []*Result {
	results := []*Result{}
	for _, leg := range legs {
		results = append(results, runLeg(ctx, settings, leg))
	}
	return results
}

// The go command's environment for a leg's build: its target and cgo, with the toolchain fixed and no
// workspace, so one toolchain builds every leg (D-TEST-15).
func legEnvironment(leg *Leg) []string {
	cgo := "0"
	if leg.Cgo {
		cgo = "1"
	}
	environment := []string{}
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		switch name {
		case "GOOS", "GOARCH", "CGO_ENABLED", "GOFLAGS", "GOWORK", "GOTOOLCHAIN":
			continue
		}
		environment = append(environment, entry)
	}
	return append(environment, "GOOS="+leg.Goos, "GOARCH="+leg.Goarch, "CGO_ENABLED="+cgo, "GOWORK=off", "GOTOOLCHAIN=local")
}

// A package with tests under a leg's build.
type legPackage struct {
	importPath string
	directory  string
}

func runLeg(ctx context.Context, settings *RunSettings, leg *Leg) *Result {
	result := &Result{Leg: leg}
	switch leg.Runner {
	case RunnerCells, RunnerNone:
		result.Outcome = OutcomeNotRun
		result.Why = leg.Why
		return result
	}
	moduleDirectory := filepath.Join(settings.Directory, leg.Module)

	// the runner's own tools first, so a host without them reads not run before anything compiles
	var runnerPath string
	switch leg.Runner {
	case RunnerNode:
		runnerPath = settings.Node
		if runnerPath == "" {
			found, err := exec.LookPath("node")
			if err != nil {
				result.Outcome = OutcomeNotRun
				result.Why = "no node on this host"
				return result
			}
			runnerPath = found
		}
	case RunnerContainer:
		runnerPath = settings.Docker
		if runnerPath == "" {
			found, err := exec.LookPath("docker")
			if err != nil {
				result.Outcome = OutcomeNotRun
				result.Why = "no docker on this host"
				return result
			}
			runnerPath = found
		}
		inspect := exec.CommandContext(ctx, runnerPath, "image", "inspect", "--format", "{{.Os}}/{{.Architecture}}", settings.ContainerImage)
		platform, err := inspect.Output()
		if err != nil {
			result.Outcome = OutcomeNotRun
			result.Why = fmt.Sprintf("no image %s on this host, and nothing here fetches one", settings.ContainerImage)
			return result
		}
		if strings.TrimSpace(string(platform)) != leg.Goos+"/"+leg.Goarch {
			result.Outcome = OutcomeNotRun
			result.Why = fmt.Sprintf("the image %s is %s, not %s/%s", settings.ContainerImage, strings.TrimSpace(string(platform)), leg.Goos, leg.Goarch)
			return result
		}
	}

	packages, err := listTestPackages(ctx, settings, leg, moduleDirectory)
	if err != nil {
		result.Outcome = OutcomeFail
		result.Why = err.Error()
		return result
	}
	if len(packages) == 0 {
		result.Outcome = OutcomeNotRun
		result.Why = "no package has tests under this leg's build"
		return result
	}
	binaryDirectory, err := os.MkdirTemp("", "sidecar-legs-")
	if err != nil {
		result.Outcome = OutcomeFail
		result.Why = err.Error()
		return result
	}
	defer os.RemoveAll(binaryDirectory)

	binaries := make([]string, len(packages))
	packageResults := make([]*PackageResult, len(packages))
	concurrency := max(1, settings.CompileConcurrency)
	slots := make(chan struct{}, concurrency)
	waitGroup := sync.WaitGroup{}
	for index, legPackage := range packages {
		waitGroup.Go(func() {
			slots <- struct{}{}
			defer func() { <-slots }()
			binary := filepath.Join(binaryDirectory, fmt.Sprintf("%03d.test", index))
			if leg.Goos == "js" {
				binary = strings.TrimSuffix(binary, ".test") + ".wasm"
			}
			arguments := []string{"test", "-c", "-o", binary}
			if 0 < len(leg.Tags) {
				arguments = append(arguments, "-tags", strings.Join(leg.Tags, ","))
			}
			arguments = append(arguments, legPackage.importPath)
			compile := exec.CommandContext(ctx, settings.Go, arguments...)
			compile.Dir = moduleDirectory
			compile.Env = legEnvironment(leg)
			output, err := compile.CombinedOutput()
			packageResults[index] = &PackageResult{ImportPath: legPackage.importPath, Output: string(output)}
			if err != nil {
				packageResults[index].Outcome = OutcomeFail
				return
			}
			binaries[index] = binary
		})
	}
	waitGroup.Wait()
	result.Packages = packageResults
	compileFailures := 0
	for _, packageResult := range packageResults {
		if packageResult.Outcome == OutcomeFail {
			compileFailures += 1
		}
	}
	if 0 < compileFailures {
		result.Outcome = OutcomeFail
		result.Why = fmt.Sprintf("%d of %d packages did not compile", compileFailures, len(packages))
		return result
	}
	if leg.Runner == RunnerCompileOnly {
		for _, packageResult := range packageResults {
			packageResult.Outcome = OutcomeCompiled
		}
		result.Outcome = OutcomeCompiled
		result.Why = leg.Why
		return result
	}

	failures := 0
	for index, legPackage := range packages {
		output, err := runBinary(ctx, settings, leg, runnerPath, binaries[index], legPackage.directory)
		packageResults[index].Output = output
		if err != nil {
			packageResults[index].Outcome = OutcomeFail
			failures += 1
		} else {
			packageResults[index].Outcome = OutcomePass
		}
	}
	if 0 < failures {
		result.Outcome = OutcomeFail
		result.Why = fmt.Sprintf("%d of %d packages failed", failures, len(packages))
		return result
	}
	result.Outcome = OutcomePass
	return result
}

// The leg's packages that hold tests under its build, through go list with the leg's environment.
func listTestPackages(ctx context.Context, settings *RunSettings, leg *Leg, moduleDirectory string) ([]*legPackage, error) {
	arguments := []string{"list", "-e", "-f", "{{if or .TestGoFiles .XTestGoFiles}}{{.ImportPath}}\t{{.Dir}}{{end}}"}
	if 0 < len(leg.Tags) {
		arguments = append(arguments, "-tags", strings.Join(leg.Tags, ","))
	}
	arguments = append(arguments, leg.Packages...)
	list := exec.CommandContext(ctx, settings.Go, arguments...)
	list.Dir = moduleDirectory
	list.Env = legEnvironment(leg)
	output, err := list.Output()
	if err != nil {
		stderr := ""
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			stderr = string(exitError.Stderr)
		}
		return nil, fmt.Errorf("listing %s's packages: %v: %s", leg.Name, err, stderr)
	}
	packages := []*legPackage{}
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		importPath, directory, found := strings.Cut(line, "\t")
		if found {
			packages = append(packages, &legPackage{importPath: importPath, directory: directory})
		}
	}
	return packages, nil
}

// One binary on its leg's runner, in its package's directory, as go test runs it there.
func runBinary(ctx context.Context, settings *RunSettings, leg *Leg, runnerPath string, binary string, packageDirectory string) (string, error) {
	testArguments := []string{"-test.count=1", "-test.v"}
	if settings.RunPattern != "" {
		testArguments = append(testArguments, "-test.run", settings.RunPattern)
	}
	if 0 < settings.TestTimeout {
		testArguments = append(testArguments, "-test.timeout", settings.TestTimeout.String())
	}
	environment := append([]string{"SIDECAR_LEG=" + leg.Name}, settings.Environment...)

	var command *exec.Cmd
	switch leg.Runner {
	case RunnerNative:
		command = exec.CommandContext(ctx, binary, testArguments...)
		command.Env = append(os.Environ(), environment...)
	case RunnerNode:
		goroot, err := exec.CommandContext(ctx, settings.Go, "env", "GOROOT").Output()
		if err != nil {
			return "", fmt.Errorf("go env GOROOT: %w", err)
		}
		execScript := filepath.Join(strings.TrimSpace(string(goroot)), "lib", "wasm", "wasm_exec_node.js")
		command = exec.CommandContext(ctx, runnerPath, append([]string{"--stack-size=8192", execScript, binary}, testArguments...)...)
		command.Env = append(os.Environ(), environment...)
	case RunnerContainer:
		suffix := make([]byte, 4)
		rand.Read(suffix)
		arguments := []string{
			"run", "--rm", "--network", "none", "--name", "sidecar-test-legs-" + hex.EncodeToString(suffix),
			"--platform", leg.Goos + "/" + leg.Goarch,
			"-v", binary + ":/sidecar-legs/test:ro", "-v", packageDirectory + ":" + packageDirectory + ":ro",
			"-w", packageDirectory, "-e", "TMPDIR=/tmp",
		}
		for _, entry := range environment {
			arguments = append(arguments, "-e", entry)
		}
		arguments = append(arguments, settings.ContainerImage, "/sidecar-legs/test")
		command = exec.CommandContext(ctx, runnerPath, append(arguments, testArguments...)...)
	default:
		return "", fmt.Errorf("%s has no runner here", leg.Name)
	}
	command.Dir = packageDirectory
	output := &bytes.Buffer{}
	command.Stdout = output
	command.Stderr = output
	err := command.Run()
	return output.String(), err
}
