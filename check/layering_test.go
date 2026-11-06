//go:build sidecar_check

// §4.7's layering row and §4.4's dependency directions. These read every Go file's syntax rather
// than a leg's closure, so an import behind a tag no leg sets, an alias, a blank import or an
// internal test file is in scope. CODESTYLE's boundary decides what counts as the package: an
// external _test package is a separately compiled consumer, and nothing else can claim to be one.

package check

import (
	"path"
	"slices"
	"strings"
	"testing"
)

// True for <svc>service and anything beneath it. §4.4 names nine, and more follow the same suffix.
func isEnginePackage(packageName string) bool {
	first, _, _ := strings.Cut(packageName, "/")
	return strings.HasSuffix(first, "service") && first != "service"
}

// True for packages that are no client: an engine may import a peer, and sidecartest hosts engines
// in one process (§22.4's T2). Everything else is a client, so a new package starts out bound.
func clientRuleExempt(packageName string) bool {
	first, _, _ := strings.Cut(packageName, "/")
	return isEnginePackage(packageName) || first == "sidecartest"
}

// True when the file builds only under the tag, so it is one of the hook files a package keeps.
func (self *sourceFile) tagOnly(tag string) bool {
	return self.constraint != nil && requiresTag(self.constraint, tag)
}

// Each file of the packages the rules bind, skipping external tests.
func (self *repository) boundFiles(t testing.TB) []*sourceFile {
	t.Helper()
	files := self.sourceFiles(t)
	boundFiles := []*sourceFile{}
	for _, file := range files {
		if !file.isExternalTest(files) {
			boundFiles = append(boundFiles, file)
		}
	}
	return boundFiles
}

// §4.4: the root imports only protocol and protocol/bridge of this repository. Internal tests are
// the package and obey it; connect/CODESTYLE.md:30-37.
func (self *repository) rootImportFindings(t testing.TB) []string {
	t.Helper()
	findings := []string{}
	for _, file := range self.boundFiles(t) {
		if file.packageName != "." {
			continue
		}
		for _, site := range file.imports() {
			relative, ours := repositoryRelative(site.importPath)
			if ours && relative != "protocol" && relative != "protocol/bridge" {
				findings = append(findings, findingf("%s:%d: the root imports %s", self.displayPath(file.path), site.line, site.importPath))
			}
		}
	}
	return findings
}

// True for the protobuf module's packages, by whole elements.
func isProtobufPackage(importPath string) bool {
	return underPath(importPath, protobufBasePath)
}

// §4.4, owner decision 52: protocol imports std, protobuf and protocol/bridge; protocol/bridge
// imports std and protobuf. Packages under them are held to the same line.
func (self *repository) protocolImportFindings(t testing.TB) []string {
	t.Helper()
	stdPackages := self.stdPackages(t)
	findings := []string{}
	for _, file := range self.boundFiles(t) {
		isBridge := underPath(file.packageName, "protocol/bridge")
		if !isBridge && !underPath(file.packageName, "protocol") {
			continue
		}
		for _, site := range file.imports() {
			relative, ours := repositoryRelative(site.importPath)
			allowed := stdPackages[site.importPath] || isProtobufPackage(site.importPath)
			if !isBridge && ours && relative == "protocol/bridge" {
				allowed = true
			}
			if !allowed {
				findings = append(findings, findingf("%s:%d: %s imports %s", self.displayPath(file.path), site.line, file.packageName, site.importPath))
			}
		}
	}
	return findings
}

// §4.4: no client package imports a <svc>service; only server does.
func (self *repository) clientEngineImportFindings(t testing.TB) []string {
	t.Helper()
	findings := []string{}
	for _, file := range self.boundFiles(t) {
		if clientRuleExempt(file.packageName) {
			continue
		}
		for _, site := range file.imports() {
			relative, ours := repositoryRelative(site.importPath)
			if ours && isEnginePackage(relative) {
				findings = append(findings, findingf("%s:%d: the client package %s imports %s", self.displayPath(file.path), site.line, file.packageName, site.importPath))
			}
		}
	}
	return findings
}

// §4.4, D-SDK-20: device imports connect and protocol/bridge only, so the iOS extension links no
// root init or protocol descriptor. Beside std it may have protobuf, whose runtime bridge's types
// are built on. A hook file under the tag may forward to the root (testhook.go), since no release
// builds it; the hygiene row holds that tag off every release.
func (self *repository) deviceImportFindings(t testing.TB) []string {
	t.Helper()
	stdPackages := self.stdPackages(t)
	findings := []string{}
	for _, file := range self.boundFiles(t) {
		if !underPath(file.packageName, "device") {
			continue
		}
		for _, site := range file.imports() {
			relative, ours := repositoryRelative(site.importPath)
			allowed := stdPackages[site.importPath] || isProtobufPackage(site.importPath) ||
				underPath(firstPartyBase(site.importPath), connectBasePath) ||
				(ours && relative == "protocol/bridge") ||
				(ours && relative == "." && file.tagOnly(sidecarTestHooksTag))
			if !allowed {
				findings = append(findings, findingf("%s:%d: device imports %s", self.displayPath(file.path), site.line, site.importPath))
			}
		}
	}
	return findings
}

// R-REPO-5: no parent package imports a child, connect/CODESTYLE.md:26. §4.4's one exception is the
// root over protocol, and protocol over protocol/bridge (owner decision 52), which the rules above
// bound; the root rule covers the rest of the root.
func (self *repository) parentImportFindings(t testing.TB) []string {
	t.Helper()
	findings := []string{}
	for _, file := range self.boundFiles(t) {
		if file.packageName == "." || file.packageName == "protocol" {
			continue
		}
		for _, site := range file.imports() {
			relative, ours := repositoryRelative(site.importPath)
			if ours && relative != file.packageName && underPath(relative, file.packageName) {
				findings = append(findings, findingf("%s:%d: %s imports its child %s", self.displayPath(file.path), site.line, file.packageName, site.importPath))
			}
		}
	}
	return findings
}

// §4.9, protos only in protocol and protocol/bridge: a .pb.go elsewhere would register outside the
// names the descriptors keep. Fixture protos live under testdata, which no walk enters.
func (self *repository) protoHomeFindings(t testing.TB) []string {
	t.Helper()
	findings := []string{}
	for _, file := range self.sourceFiles(t) {
		if strings.HasSuffix(path.Base(file.path), ".pb.go") && !slices.Contains([]string{"protocol", "protocol/bridge"}, file.packageName) {
			findings = append(findings, findingf("%s: generated protobuf outside protocol and protocol/bridge", self.displayPath(file.path)))
		}
	}
	return findings
}
