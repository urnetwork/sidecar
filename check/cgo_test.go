//go:build sidecar_check

// §4.7's cgo row: CgoFiles, except keychain_darwin.go in §5.10's darwin fallback leg (R-REPO-6;
// D-REPO-4). A leg's listing sees a cgo file only under the tags and system the leg builds, and only
// with cgo on, while a CGO_ENABLED=0 leg, which is every CLI release target, sees none at all. So
// two readings: every file's syntax, for what no leg compiles, and every leg's CgoFiles, for what
// each compiles, third-party packages included.

package check

import (
	"path"
	"path/filepath"
	"testing"
)

// The one cgo file §4.7 allows.
const keychainCgoFileName = "keychain_darwin.go"

// A cgo file in this repository, whatever its constraints, other than the keychain's, which §4.4
// keeps in cli/ or the root.
func (self *repository) cgoSourceFindings(t testing.TB) []string {
	t.Helper()
	findings := []string{}
	for _, file := range self.sourceFiles(t) {
		for _, site := range file.imports() {
			if site.importPath != "C" {
				continue
			}
			keychain := filepath.Base(file.path) == keychainCgoFileName && (file.packageName == "." || file.packageName == "cli")
			if !keychain {
				findings = append(findings, findingf("%s:%d: imports C", self.displayPath(file.path), site.line))
			}
		}
	}
	return findings
}

// Each leg's CgoFiles. In this repository only the keychain's file on a fallback leg passes, in the
// package cgoSourceFindings allows it in, since a leg can link a directory that walk skips. A
// third-party file passes where settings name it; std's are the toolchain's own, and are not ours
// to rule on (net and os/user turn to cgo on any CGO_ENABLED=1 leg).
func (self *repository) cgoLegFindings(t testing.TB) []string {
	t.Helper()
	findings := []string{}
	for _, leg := range self.legs {
		for _, listed := range self.closure(t, leg) {
			if listed.Standard || listed.Module == nil {
				continue
			}
			relative, ours := repositoryRelative(listed.ImportPath)
			for _, cgoFile := range listed.CgoFiles {
				if ours {
					keychainPackage := relative == "." || relative == "cli"
					if cgoFile == keychainCgoFileName && keychainPackage && leg.keychainFallback {
						continue
					}
					findings = append(findings, findingf("%s compiles the cgo file %s in %s", leg.name, cgoFile, listed.ImportPath))
					continue
				}
				if _, listedFile := self.settings.thirdPartyCgoFiles[path.Join(listed.ImportPath, cgoFile)]; !listedFile {
					findings = append(findings, findingf("%s compiles the third-party cgo file %s in %s", leg.name, cgoFile, listed.ImportPath))
				}
			}
		}
	}
	return findings
}
