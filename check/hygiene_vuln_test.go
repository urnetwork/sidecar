//go:build sidecar_check

// §4.7's hygiene row: govulncheck findings, on every shipped leg. govulncheck reads a leg's own
// source graph, GOOS, GOARCH and tags included, and follows calls, so a finding is a vulnerable
// symbol that leg reaches. A vulnerability in a module the leg requires but never calls is not one;
// it is what the tool itself reports as not affecting the code, and it shows in the log.
//
// The scanner is fetched at a pinned version with go install, so no go.mod here requires it and no
// consumer's graph grows. Fetching it needs the module proxy, and scanning needs the database: where
// either is out of reach the rule fails, because a scan that did not run found nothing.

package check

import (
	"errors"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

// The exit status govulncheck gives when a scan finds a vulnerable symbol reached.
const govulncheckFoundExitCode = 3

// Installs the pinned scanner into a temporary directory and returns its path.
func (self *repository) installGovulncheck(t testing.TB) string {
	t.Helper()
	directory := t.TempDir()
	// from the temporary directory, so no go.mod here takes part in the install
	_, err := runGo(directory, goEnvironment("GOBIN="+directory), "install", "golang.org/x/vuln/cmd/govulncheck@"+self.settings.govulncheckVersion)
	if err != nil {
		t.Fatalf("installing govulncheck: %v", err)
	}
	return filepath.Join(directory, "govulncheck")
}

// One leg's scan: its finding, or nothing. Every leg scans with CGO_ENABLED=0. Loading a package with
// cgo on needs that target's C compiler, which a host has for its own target at most, and a scan
// follows Go calls, so only what cgo swaps out of net and os/user differs. It runs off the test's
// goroutine, so what goes wrong comes back as a finding.
func (self *repository) scanLeg(scanner string, leg *buildLeg) []string {
	directory, err := self.legDirectory(leg)
	if err != nil {
		return []string{err.Error()}
	}
	patterns, err := self.legPatterns(leg)
	if err != nil {
		return []string{err.Error()}
	}
	if len(patterns) == 0 {
		return nil
	}
	arguments := []string{"-db=" + self.settings.vulnDatabase}
	if len(leg.tags) != 0 {
		arguments = append(arguments, "-tags="+strings.Join(leg.tags, ","))
	}
	arguments = append(arguments, patterns...)
	command := exec.Command(scanner, arguments...)
	command.Dir = directory
	command.Env = append(leg.environment(), "CGO_ENABLED=0")
	output, err := command.CombinedOutput()
	if err == nil {
		return nil
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) && exitError.ExitCode() == govulncheckFoundExitCode {
		return []string{findingf("%s:\n%s", leg.name, output)}
	}
	return []string{findingf("%s: govulncheck did not finish: %v\n%s", leg.name, err, output)}
}

// The scan over every shipped leg, some at once. A panic-free scan of each is the pass; see the file
// comment for what counts.
func (self *repository) vulnFindings(scanner string) []string {
	legs := self.shippedLegs()
	concurrency := max(self.settings.vulnScanConcurrency, 1)
	slots := make(chan struct{}, concurrency)
	findingLock := sync.Mutex{}
	findings := []string{}
	waitGroup := sync.WaitGroup{}
	for _, leg := range legs {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			legFindings := self.scanLeg(scanner, leg)
			func() {
				findingLock.Lock()
				defer findingLock.Unlock()
				findings = append(findings, legFindings...)
			}()
		}()
	}
	waitGroup.Wait()
	slices.Sort(findings)
	return findings
}
