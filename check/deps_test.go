//go:build sidecar_check

// §4.7's deps row: what a leg may link, what the root may require, which golang.org/x/text every leg
// selects, and what dependencies.yml says about each module. A license is read off the module's own
// files, because an id in a table is a claim, and a rule that only checks the claim enforces nothing.

package check

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// Modules no leg may link and no sidecar module may require, whatever dependencies.yml says, with
// what each is. server, sdk and sn by owner rule 2; proxy and userwireguard by §4.7's imports bullet,
// since cli's ur proxy add runs on connect.Tun instead; the message repo by owner rule 3; and the
// three that §4.5's ServiceHost exists to keep out of sidecar.
var refusedModules = map[string]string{
	serverBasePath:                        "server, which imports sidecar",
	sdkBasePath:                           "sdk, which imports sidecar",
	snBasePath:                            "sn, which imports sidecar",
	urnetworkPrefix + "proxy":             "proxy, which §4.7 keeps out",
	urnetworkPrefix + "message":           "the deleted message repo (owner rule 3)",
	urnetworkPrefix + "userwireguard":     "userwireguard, which §4.7 keeps out",
	"github.com/redis/go-redis":           "go-redis, which only ServiceHost's implementation may use",
	"github.com/minio/minio-go":           "minio-go, which only ServiceHost's implementation may use",
	"github.com/prometheus/client_golang": "prometheus, which only ServiceHost's implementation may use",
}

// The first-party modules a sidecar module may require beside this repository's own (§4.7).
var allowedFirstPartyModules = []string{connectBasePath, glogBasePath}

// One dependencies.yml row.
type dependencyRow struct {
	module string
	// an SPDX id, or ids joined by AND where a module's files carry several licenses
	spdx   string
	reason string
	// client, engine, cli, test
	legs []string
	// §4.7 names the module but nothing links it yet, so nothing can be read from its files
	planned bool
	line    int
}

// Reads dependencies.yml's one shape. Anything else in the file fails, because a row a parser skips
// is a module the deps row thinks is unlisted or, worse, a field it thinks is absent: the file stays
// plain enough that a YAML reader and this one agree on it.
func parseDependencies(data string) ([]*dependencyRow, []string) {
	rows := []*dependencyRow{}
	findings := []string{}
	var row *dependencyRow
	sawModules := false
	for index, line := range strings.Split(data, "\n") {
		lineNumber := index + 1
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if line == "modules:" {
			sawModules = true
			continue
		}
		entry := strings.TrimPrefix(line, "  - ")
		if entry != line {
			row = &dependencyRow{line: lineNumber}
			rows = append(rows, row)
		} else {
			entry = strings.TrimPrefix(line, "    ")
		}
		key, value, found := strings.Cut(entry, ": ")
		if entry == line || !found || row == nil || !sawModules {
			findings = append(findings, findingf("dependencies.yml:%d: cannot read %q", lineNumber, line))
			continue
		}
		if strings.Contains(value, ": ") || strings.Contains(value, " #") {
			findings = append(findings, findingf("dependencies.yml:%d: a value holds ': ' or ' #', which YAML would read otherwise", lineNumber))
		}
		switch key {
		case "module":
			row.module = value
		case "spdx":
			row.spdx = value
		case "reason":
			row.reason = value
		case "leg":
			if !strings.HasPrefix(value, "[") || !strings.HasSuffix(value, "]") {
				findings = append(findings, findingf("dependencies.yml:%d: leg is not a [list]", lineNumber))
				continue
			}
			for _, class := range strings.Split(strings.Trim(value, "[]"), ",") {
				row.legs = append(row.legs, strings.TrimSpace(class))
			}
		case "planned":
			if value != "true" {
				findings = append(findings, findingf("dependencies.yml:%d: planned is true or absent", lineNumber))
			}
			row.planned = true
		default:
			findings = append(findings, findingf("dependencies.yml:%d: unknown field %s", lineNumber, key))
		}
	}
	if !sawModules {
		findings = append(findings, "dependencies.yml has no modules: list")
	}
	seen := map[string]bool{}
	for _, row := range rows {
		if row.module == "" || row.spdx == "" || row.reason == "" || len(row.legs) == 0 {
			findings = append(findings, findingf("dependencies.yml:%d: a row needs module, spdx, reason and leg", row.line))
		}
		if seen[row.module] {
			findings = append(findings, findingf("dependencies.yml:%d: %s is listed twice", row.line, row.module))
		}
		seen[row.module] = true
		for _, class := range row.legs {
			if !slices.Contains([]string{classClient, classEngine, classCli, classSidecarctl, classTest}, class) {
				findings = append(findings, findingf("dependencies.yml:%d: %s is not a leg", row.line, class))
			}
		}
	}
	return rows, findings
}

// The rows, with what dependencies.yml itself got wrong as findings.
func (self *repository) dependencyRows(t testing.TB) (map[string]*dependencyRow, []string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(self.moduleDirectory, "dependencies.yml"))
	if err != nil {
		return nil, []string{findingf("reading dependencies.yml: %v", err)}
	}
	rows, findings := parseDependencies(string(data))
	rowsByModule := map[string]*dependencyRow{}
	for _, row := range rows {
		rowsByModule[row.module] = row
	}
	return rowsByModule, findings
}

// The refused module a path falls under, by whole elements, on a release spelling too.
func refusedModule(modulePath string) (string, bool) {
	base := firstPartyBase(modulePath)
	for root, what := range refusedModules {
		if underPath(base, root) {
			return what, true
		}
	}
	return "", false
}

// Fails on a refused module in a leg's closure, a module dependencies.yml does not list, or a module
// linked on a leg its row does not name. A test leg asks only that the module is listed, because a
// client module may well appear in a test's closure too.
func (self *repository) legModuleFindings(t testing.TB) []string {
	t.Helper()
	rowsByModule, findings := self.dependencyRows(t)
	for _, leg := range self.legs {
		reported := map[string]bool{}
		for _, listed := range self.closure(t, leg) {
			if listed.Module == nil || underPath(firstPartyBase(listed.Module.Path), sidecarBasePath) {
				continue
			}
			modulePath := firstPartyBase(listed.Module.Path)
			if reported[modulePath] {
				continue
			}
			reported[modulePath] = true
			if what, refused := refusedModule(modulePath); refused {
				findings = append(findings, findingf("%s links %s, from %s", leg.name, listed.ImportPath, what))
				continue
			}
			row, listedRow := rowsByModule[modulePath]
			if !listedRow {
				findings = append(findings, findingf("%s links %s, and dependencies.yml does not list %s", leg.name, listed.ImportPath, modulePath))
				continue
			}
			if row.planned {
				// its license is read from its files from now on, so all this leaves is a stale field
				self.report("a leg links %s, whose row can drop planned", modulePath)
			}
			if leg.class != classTest && !slices.Contains(row.legs, leg.class) {
				findings = append(findings, findingf("%s is a %s leg and links %s, whose row names %v", leg.name, leg.class, modulePath, row.legs))
			}
		}
	}
	slices.Sort(findings)
	return findings
}

// Each row no leg links, unless the row says planned: a stale row reads as permission for a module
// nothing has reviewed since it left.
func (self *repository) staleRowFindings(t testing.TB) []string {
	t.Helper()
	rowsByModule, findings := self.dependencyRows(t)
	linked := map[string]bool{}
	for _, leg := range self.legs {
		for _, listed := range self.closure(t, leg) {
			if listed.Module != nil {
				linked[firstPartyBase(listed.Module.Path)] = true
			}
		}
	}
	for modulePath, row := range rowsByModule {
		if !row.planned && !linked[modulePath] {
			findings = append(findings, findingf("dependencies.yml:%d: no leg links %s", row.line, modulePath))
		}
	}
	slices.Sort(findings)
	return findings
}

// §4.7: the root module requires no module of this repository, or a consumer's graph would hold
// cli's and smtpproof's requirements.
func (self *repository) rootRequireFindings(t testing.TB) []string {
	t.Helper()
	root := self.module(t, ".")
	if root == nil {
		return []string{"no root module"}
	}
	findings := []string{}
	for _, require := range root.file.Require {
		if underPath(firstPartyBase(require.Path), sidecarBasePath) {
			findings = append(findings, findingf("the root module requires %s, a module of this repository", require.Path))
		}
	}
	return findings
}

// §4.7's imports bullet at the module-file level, where a require no package reaches still shows:
// no sidecar module requires a refused module, or any first-party module beside this repository's
// own, connect and connect's replaced forks.
func (self *repository) firstPartyRequireFindings(t testing.TB) []string {
	t.Helper()
	findings := []string{}
	for _, module := range self.modules(t) {
		for _, require := range module.file.Require {
			base := firstPartyBase(require.Path)
			if underPath(base, sidecarBasePath) || slices.Contains(allowedFirstPartyModules, base) {
				continue
			}
			what, refused := refusedModule(base)
			switch {
			case refused:
				findings = append(findings, findingf("%s requires %s, %s", module.relativeName, require.Path, what))
			case strings.HasPrefix(base, urnetworkPrefix), strings.HasPrefix(base, urfoundationPrefix):
				findings = append(findings, findingf("%s requires %s, a first-party module §4.7 does not name", module.relativeName, require.Path))
			}
		}
	}
	return findings
}

// §4.7's module table and C-23's sidecarctl: these five and no other, each covered by a leg. A module
// added here is either given a leg or fails, so nothing builds out of the rows' sight.
func (self *repository) moduleSetFindings(t testing.TB) []string {
	t.Helper()
	findings := []string{}
	seen := map[string]bool{}
	for _, module := range self.modules(t) {
		if !slices.Contains([]string{".", "cli", "smtpproof", "mlsinterop", "sidecarctl"}, module.relativeName) {
			findings = append(findings, findingf("%s is the module %s, which is not in §4.7's table", self.displayPath(module.directory), module.file.Module.Path))
		}
		if seen[module.relativeName] {
			findings = append(findings, findingf("two module files claim %s", module.basePath))
		}
		seen[module.relativeName] = true
		covered := slices.ContainsFunc(self.legs, func(leg *buildLeg) bool {
			return leg.moduleName == module.relativeName
		})
		if !covered {
			findings = append(findings, findingf("no leg reads the module %s", module.basePath))
		}
	}
	for _, leg := range self.legs {
		if !seen[leg.moduleName] {
			findings = append(findings, findingf("%s reads the module %s, which this checkout does not hold", leg.name, leg.moduleName))
		}
	}
	slices.Sort(findings)
	return findings
}

// §4.7 and §11.14: what each module of this repository selects, then what each sdk module requires.
// sdk's legs build under sdk's modules, and gomobile's under sdk/build, so a sidecar module's own
// selection is not the last word on those legs. Each must be normalizer 1's exact version, because
// another version is another normalizer and a rebuild of every index.
func (self *repository) xTextFindings(t testing.TB) []string {
	t.Helper()
	want := self.settings.normalizerOneXTextVersion
	findings := []string{}
	for _, module := range self.modules(t) {
		output, err := runGo(module.directory, goEnvironment(), "list", "-m", "-e", "-f", "{{.Version}}|{{if .Replace}}{{.Replace.Path}}{{end}}|{{if .Error}}{{.Error}}{{end}}", xTextBasePath)
		if err != nil {
			t.Fatal(err)
		}
		version, rest, _ := strings.Cut(strings.TrimSpace(string(output)), "|")
		replacedBy, listError, _ := strings.Cut(rest, "|")
		if strings.Contains(listError, "not a known dependency") {
			// a module requiring nothing selects no x/text, and selects no wrong one
			continue
		}
		if listError != "" {
			findings = append(findings, findingf("%s: go list -m %s: %s", module.relativeName, xTextBasePath, listError))
			continue
		}
		if version != want {
			findings = append(findings, findingf("%s selects %s %s, and normalizer 1's is %s", module.relativeName, xTextBasePath, version, want))
		}
		if replacedBy != "" {
			findings = append(findings, findingf("%s replaces %s with %s", module.relativeName, xTextBasePath, replacedBy))
		}
	}
	for _, sibling := range []string{"sdk", "sdk/js", "sdk/cgo", "sdk/build"} {
		file, err := self.siblingModuleFile(sibling)
		if err != nil {
			findings = append(findings, findingf("reading %s's x/text: %v", sibling, err))
			continue
		}
		for _, require := range file.Require {
			if require.Path == xTextBasePath && require.Version != want {
				findings = append(findings, findingf("%s requires %s %s, and normalizer 1's is %s", sibling, xTextBasePath, require.Version, want))
			}
		}
	}
	return findings
}

// §4.7's versions bullet: a module a leg links matches what connect, sdk and server require, since
// an uncoordinated bump fails server's -mod=readonly build.
func (self *repository) sharedVersionFindings(t testing.TB) []string {
	t.Helper()
	findings := []string{}
	siblingVersions := map[string]map[string]string{}
	for _, sibling := range []string{"connect", "sdk", "server"} {
		file, err := self.siblingModuleFile(sibling)
		if err != nil {
			findings = append(findings, findingf("reading %s's requirements: %v", sibling, err))
			continue
		}
		versions := map[string]string{}
		for _, require := range file.Require {
			versions[require.Path] = require.Version
		}
		siblingVersions[sibling] = versions
	}
	reported := map[string]bool{}
	for _, leg := range self.legs {
		for _, listed := range self.closure(t, leg) {
			if listed.Module == nil || strings.HasPrefix(listed.Module.Path, urnetworkPrefix) {
				continue
			}
			for sibling, versions := range siblingVersions {
				version, shared := versions[listed.Module.Path]
				key := sibling + " " + listed.Module.Path
				if shared && version != listed.Module.Version && !reported[key] {
					reported[key] = true
					findings = append(findings, findingf("%s links %s %s, and %s requires %s", leg.name, listed.Module.Path, listed.Module.Version, sibling, version))
				}
			}
		}
	}
	slices.Sort(findings)
	return findings
}

// Phrases that name what a license file's words beyond its licenses' own are: the refused families,
// and custom clauses everyone knows. Any word beyond a row's licenses fails it, so these add only the
// refusal's name to a finding; one in a license's own text, such as X11's advertising clause under an
// X11 row, is that license's and passes.
var refusedLicensePhrases = []string{
	"gnu general public license",
	"gnu lesser general public",
	"gnu affero general public",
	"server side public license",
	"business source license",
	"commons clause",
	"shall be used for good, not evil",
	"shall not be used in advertising",
	"all advertising materials mentioning features or use of this software",
	"non-commercial",
}

// A license file by its name, as the go command's own license scan finds them.
var licenseFileNamePattern = regexp.MustCompile(`(?i)^(licen[cs]e|copying|unlicense)([.-].*)?$`)

// Each id in a row's spdx, joined by AND.
func licenseIds(spdx string) []string {
	return strings.Split(spdx, " AND ")
}

// One license file a leg links, read.
type linkedLicenseFile struct {
	// from its module's top, for a finding
	name string
	// at the module's top, rather than beside or above a package the leg links
	top   bool
	words []string
}

// What is wrong with one copy of a row's module, given the license files its linked packages sit
// under and §4.7's texts: an id §4.7 does not allow; no license file at the module's top; a file with
// words beyond the row's licenses and the module's notes, which makes it a custom license, with the
// refused phrases among those words; or an id no file shows. Each file is read on its own, so a GPL
// file beside a linked package fails an MIT row as surely as one at the top.
func (self *checkSettings) licenseFindings(row *dependencyRow, files []*linkedLicenseFile, texts map[string][]*licenseText) []string {
	findings := []string{}
	rowTexts := []*licenseText{}
	for _, id := range licenseIds(row.spdx) {
		if !slices.Contains(self.allowedLicenses, id) {
			findings = append(findings, findingf("%s is %s, which §4.7 does not allow", row.module, id))
			continue
		}
		rowTexts = append(rowTexts, texts[id]...)
	}
	note := self.licenseNotes[row.module]
	for _, passage := range note.passages {
		items, err := parseLicenseTemplate(passage)
		if err != nil {
			findings = append(findings, findingf("%s's license note cannot be read: %v", row.module, err))
			continue
		}
		rowTexts = append(rowTexts, &licenseText{id: row.module, name: "note", items: items})
	}
	if !slices.ContainsFunc(files, func(file *linkedLicenseFile) bool { return file.top }) {
		return append(findings, findingf("%s has no license file, and §4.7 refuses the unlicensed", row.module))
	}
	refusedPhraseWords := map[string]string{}
	for _, phrase := range refusedLicensePhrases {
		refusedPhraseWords[phrase] = " " + strings.Join(licenseWords(phrase), " ") + " "
	}
	shownIds := map[string]bool{}
	for _, file := range files {
		covered := make([]bool, len(file.words))
		for id := range self.coverLicenseWords(file.words, covered, rowTexts) {
			shownIds[id] = true
		}
		beyond := []string{}
		for index, word := range file.words {
			if !covered[index] {
				beyond = append(beyond, word)
			}
		}
		if len(beyond) == 0 {
			continue
		}
		findings = append(findings, findingf("%s's %s holds words beyond %s, so it is another license or a custom one: it leaves %s at %s",
			row.module, file.name, row.spdx, row.spdx, self.licenseDeparture(file.words, covered, rowTexts)))
		beyondText := " " + strings.Join(beyond, " ") + " "
		for _, phrase := range refusedLicensePhrases {
			if strings.Contains(beyondText, refusedPhraseWords[phrase]) {
				findings = append(findings, findingf("%s's %s has %q", row.module, file.name, phrase))
			}
		}
	}
	for _, id := range licenseIds(row.spdx) {
		if slices.Contains(self.allowedLicenses, id) && !shownIds[id] {
			findings = append(findings, findingf("%s says %s, and none of its license files holds %s's text", row.module, id, id))
		}
	}
	return findings
}

// One copy of a module some leg links.
type linkedModuleCopy struct {
	directory string
	version   string
}

// The license files that bear on a copy's linked packages: those at the module's top, and those in
// each linked package's directory and every directory between it and the top, which is where a
// license file covering that package can sit. A file in a directory no linked package is under says
// nothing about what ships.
func readLinkedLicenseFiles(moduleDirectory string, packageDirectories map[string]bool) ([]*linkedLicenseFile, error) {
	directories := map[string]bool{moduleDirectory: true}
	for packageDirectory := range packageDirectories {
		for directory := packageDirectory; directory != moduleDirectory; directory = filepath.Dir(directory) {
			relative, err := filepath.Rel(moduleDirectory, directory)
			if err != nil || !filepath.IsLocal(relative) {
				return nil, fmt.Errorf("%s is outside its module at %s", packageDirectory, moduleDirectory)
			}
			directories[directory] = true
		}
	}
	files := []*linkedLicenseFile{}
	for _, directory := range slices.Sorted(maps.Keys(directories)) {
		entries, err := os.ReadDir(directory)
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			if entry.IsDir() || !licenseFileNamePattern.MatchString(entry.Name()) {
				continue
			}
			filePath := filepath.Join(directory, entry.Name())
			data, err := os.ReadFile(filePath)
			if err != nil {
				return nil, err
			}
			relative, err := filepath.Rel(moduleDirectory, filePath)
			if err != nil {
				return nil, err
			}
			files = append(files, &linkedLicenseFile{name: filepath.ToSlash(relative), top: directory == moduleDirectory, words: licenseWords(string(data))})
		}
	}
	return files, nil
}

// Every row's id against §4.7's list, and the license files of every copy a leg links against its
// row. Each module of this repository selects versions of its own, and mlsinterop requires nothing of
// the root, so a module can stand at two versions: one copy's files say nothing about the other's. A
// planned row has no files to read yet, so its id alone is checked, and its module joins the file
// check the moment a leg links it, planned or not.
func (self *repository) licenseRowFindings(t testing.TB) []string {
	t.Helper()
	rowsByModule, findings := self.dependencyRows(t)
	texts, err := licenseTexts()
	if err != nil {
		return append(findings, findingf("reading §4.7's licenses' texts: %v", err))
	}
	moduleCopies := map[string]map[linkedModuleCopy]map[string]bool{}
	for _, leg := range self.legs {
		for _, listed := range self.closure(t, leg) {
			if listed.Module == nil {
				continue
			}
			modulePath := firstPartyBase(listed.Module.Path)
			if moduleCopies[modulePath] == nil {
				moduleCopies[modulePath] = map[linkedModuleCopy]map[string]bool{}
			}
			linkedCopy := linkedModuleCopy{directory: listed.Module.Dir, version: listed.Module.Version}
			if moduleCopies[modulePath][linkedCopy] == nil {
				moduleCopies[modulePath][linkedCopy] = map[string]bool{}
			}
			moduleCopies[modulePath][linkedCopy][listed.Dir] = true
		}
	}
	for modulePath, row := range rowsByModule {
		copies, linked := moduleCopies[modulePath]
		if !linked {
			for _, id := range licenseIds(row.spdx) {
				if !slices.Contains(self.settings.allowedLicenses, id) {
					findings = append(findings, findingf("%s is %s, which §4.7 does not allow", modulePath, id))
				}
			}
			continue
		}
		for linkedCopy, packageDirectories := range copies {
			files, err := readLinkedLicenseFiles(linkedCopy.directory, packageDirectories)
			if err != nil {
				findings = append(findings, findingf("reading %s's license files at %s: %v", modulePath, linkedCopy.version, err))
				continue
			}
			for _, finding := range self.settings.licenseFindings(row, files, texts) {
				findings = append(findings, findingf("%s, at %s", finding, linkedCopy.version))
			}
		}
	}
	slices.Sort(findings)
	return findings
}
