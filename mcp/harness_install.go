//go:build !js && !ios && !android && !sdk_mobile_bind

// `ur install-harness <claude-code|codex|cursor> [--agent <n>] [--instance <i>] [--project]` (§16.7, R-MCP-2, D-MCP-5,
// D-MCP-9, I-9; MCP-M3-16): ur's MCP entry, the ask rule naming each outward tool, and the hooks, in the harness's own
// files, shown as a diff and then written, and a seal of what ur installed for the config check (harness_hash.go).
//
//	template   everything ur writes is one function of the harness, ur's absolute path (§4.10), the agent, the
//	           instance and the outward tools, so the seal names those inputs and re-running the install restores
//	           ur's entries: the sealed value comes from the template, never from a file as found (QD-103)
//	tools      the outward tools are §16.5's catalog's O tier (catalog.go), so a new O tool is asked about with no
//	           change here
//	edits      each file is brought to hold the template's entries by exact edits (harness_config.go): a missing
//	           entry inserted, a changed one replaced in place, a stale or second one of ur's removed, and nothing
//	           else touched, so a person's settings stay byte for byte; a file already holding them is left as it is
//	hooks      fail open (D-MCP-5): ur hook exits 0 whatever happens, and a lapse taints the run instead
//	           (hook_coverage.go). The fail-closed form a Team's record_required asks for is M6's (plan-MCP-record-
//	           required), so no hook entry carries onFailure, failClosed or --required yet
//	write      each file by a temporary file in its own directory, synced, then renamed over it; a file the harness
//	           rewrote between the plan and the write is planned again from its new bytes, up to
//	           Ingest.HarnessInstallRetryCount times, since only ur's entries change and the person saw those
//	--project  the files a cloud session loads, committed in the project, and §5.8's `.ur` where none is
//
// The vault-synced global harness config is plan-MCP-harness-config-schema's: until a reader of the vault's
// harness/config.json lands, the install takes local defaults and reads no vault (QD-116's interim).
//
// Package-level functions are safe for concurrent use.

package mcp

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
)

// The harnesses ur installs into, as `ur install-harness` and `ur hook` name them.
func HarnessNames() []string {
	names := []string{}
	for name := range harnessInstallAdapters {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// A harness name ur does not install into.
var ErrHarnessUnknown = errors.New("no such harness")

// §16.5's outward tools, sorted: the catalog's O tier, which every ask rule names.
func McpOutwardToolNames() []string {
	names := []string{}
	for _, design := range mcpCatalogDesign {
		if design.tier == McpTierOutward {
			names = append(names, design.name)
		}
	}
	slices.Sort(names)
	return names
}

// Whether path, raw names joined by /, is one of a shared repo's agent-config files (§16.5's evs_write row): an entry
// of Ingest.AgentConfigPaths with no / matching its last name, one with a / matching it whole or its tail after a /.
func McpAgentConfigPath(ingest *sidecar.SidecarIngestSettings, path string) bool {
	name := path
	if index := strings.LastIndexByte(path, '/'); 0 <= index {
		name = path[index+1:]
	}
	for _, entry := range ingest.AgentConfigPaths {
		if !strings.Contains(entry, "/") {
			if name == entry {
				return true
			}
			continue
		}
		if path == entry || strings.HasSuffix(path, "/"+entry) {
			return true
		}
	}
	return false
}

// What one install is: the template's inputs and where its files go.
type HarnessInstallArgs struct {
	Harness string
	// The agent label every MCP session of the entry acts as, "" for none (§5.8's --agent).
	Agent string
	// The daemon's instance; the default one is named nowhere.
	Instance string
	// A project install's directory, absolute; "" installs into the person's own files.
	ProjectDirectory string
	// The person's home, absolute: where a user install's files go.
	Home string
	// ur's absolute path, which every command names (§4.10).
	UrPath string
	// The instance's <state>, where the seal goes.
	StateDirectory string
	Ingest         *sidecar.SidecarIngestSettings
}

// The template's inputs: what ur writes into a harness's files is a function of these alone.
type harnessTemplate struct {
	harness  string
	urPath   string
	agent    string
	instance string
	// sorted
	outwardTools []string
	// in whole seconds
	permissionTimeoutSeconds int
}

// The template of args, its outward tools the catalog's.
func newHarnessTemplate(harness string, urPath string, agent string, instance string, outwardTools []string, ingest *sidecar.SidecarIngestSettings) *harnessTemplate {
	if instance == sidecar.DefaultSidecarSettings().Instance {
		instance = ""
	}
	tools := slices.Clone(outwardTools)
	slices.Sort(tools)
	return &harnessTemplate{
		harness:                  harness,
		urPath:                   urPath,
		agent:                    agent,
		instance:                 instance,
		outwardTools:             tools,
		permissionTimeoutSeconds: int(ingest.PermissionHookTimeout / time.Second),
	}
}

// The MCP entry's arguments: ur mcp, its agent and its instance.
func (self *harnessTemplate) mcpArgs() []string {
	args := []string{"mcp"}
	if self.agent != "" {
		args = append(args, "--agent", self.agent)
	}
	if self.instance != "" {
		args = append(args, "--instance", self.instance)
	}
	return args
}

// The hook command: ur hook <harness>, by ur's absolute path, quoted for the shell a harness runs it in.
func (self *harnessTemplate) hookCommand() string {
	command := harnessShellQuote(self.urPath) + " hook " + self.harness
	if self.instance != "" {
		command += " --instance " + harnessShellQuote(self.instance)
	}
	return command
}

// text as one shell word: bare where it holds only safe bytes, else in single quotes.
func harnessShellQuote(text string) string {
	safe := text != ""
	for _, r := range text {
		if !(('a' <= r && r <= 'z') || ('A' <= r && r <= 'Z') || ('0' <= r && r <= '9') || strings.ContainsRune("/._-+:@%=,", r)) {
			safe = false
			break
		}
	}
	if safe {
		return text
	}
	return "'" + strings.ReplaceAll(text, "'", `'\''`) + "'"
}

// A shell command's words, by POSIX quoting: single quotes literal, double quotes with \ escaping $ ` " \ and a
// newline, a bare \ escaping the next byte. Enough to read ur's own commands and the first word of anyone's.
func harnessShellWords(command string) []string {
	words := []string{}
	word := strings.Builder{}
	inWord := false
	for i := 0; i < len(command); i += 1 {
		c := command[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n':
			if inWord {
				words = append(words, word.String())
				word.Reset()
				inWord = false
			}
		case c == '\'':
			inWord = true
			end := strings.IndexByte(command[i+1:], '\'')
			if end < 0 {
				word.WriteString(command[i+1:])
				i = len(command)
				continue
			}
			word.WriteString(command[i+1 : i+1+end])
			i += end + 1
		case c == '"':
			inWord = true
			i += 1
			for ; i < len(command) && command[i] != '"'; i += 1 {
				if command[i] == '\\' && i+1 < len(command) && strings.ContainsRune("$`\"\\\n", rune(command[i+1])) {
					i += 1
				}
				word.WriteByte(command[i])
			}
		case c == '\\' && i+1 < len(command):
			inWord = true
			i += 1
			word.WriteByte(command[i])
		default:
			inWord = true
			word.WriteByte(c)
		}
	}
	if inWord {
		words = append(words, word.String())
	}
	return words
}

// Whether a hook command is any ur's `ur hook`: its first word's base name ur, its second hook. The install replaces
// every one of these, an older ur's included.
func harnessUrishCommand(command string) bool {
	words := harnessShellWords(command)
	if len(words) < 2 || words[1] != "hook" {
		return false
	}
	base := strings.ToLower(filepath.Base(strings.ReplaceAll(words[0], `\`, "/")))
	return strings.TrimSuffix(base, ".exe") == urBinaryName
}

// Whether a hook command is this ur's: its first word ur's absolute path exactly, its second hook.
func (self *harnessTemplate) ownsCommand(command string) bool {
	words := harnessShellWords(command)
	return 2 <= len(words) && words[0] == self.urPath && words[1] == "hook"
}

// One kind of file ur writes entries into.
type harnessFileKind interface {
	// ur's entries the template puts in the file, as JSON's values once normalized: what the seal hashes.
	template(template *harnessTemplate) (any, error)
	// The next exact edit that brings content toward holding the template's entries, nil once it does.
	nextEdit(content []byte, template *harnessTemplate, maxDepth int) (*harnessEdit, error)
	// The entries of this ur's that content holds, as JSON's values; the same shape as template's.
	extract(content []byte, template *harnessTemplate, maxDepth int) (any, error)
	// How many entries content holds that are not this ur's and can answer for one of its tools: a hook on a
	// permission or pre-tool event whose matcher covers ur's server, or an allow rule naming it (QD-103).
	competing(content []byte, template *harnessTemplate, maxDepth int) (int, error)
}

// One file of a harness's install.
type harnessFile struct {
	// absolute
	path string
	// a new file's
	mode os.FileMode
	kind harnessFileKind
}

// A harness's install: its files for a scope, and the settings files of a session's working directory.
type harnessInstallAdapter interface {
	// The files a user install writes under home, or a project install under directory.
	files(home string, projectDirectory string) []*harnessFile
	// The settings files of a session's working directory, whose competing entries the check counts at
	// SessionStart (QD-103).
	projectSettingsFiles(cwd string) []*harnessFile
}

// The adapters, by harness.
var harnessInstallAdapters = map[string]harnessInstallAdapter{
	claudeHookHarness: &claudeInstallAdapter{},
	codexHookHarness:  &codexInstallAdapter{},
	cursorHookHarness: &cursorInstallAdapter{},
}

// The mode a new file of a scope gets: the person's own files 0600, a project's committed ones 0644.
func harnessFileMode(projectDirectory string) os.FileMode {
	if projectDirectory != "" {
		return 0o644
	}
	return 0o600
}

// SHA-256 of ur's entries, value as JSON's, in RFC 8785's form (QD-103).
func harnessEntriesSha256(value any) ([sha256.Size]byte, error) {
	encoded, err := harnessJsonEncode(value, "", "")
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	canonical, err := sidecar.CanonicalJson([]byte(encoded))
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(canonical), nil
}

// The template's entries for file, normalized as a read-back is.
func harnessTemplateEntries(file *harnessFile, template *harnessTemplate) (any, error) {
	value, err := file.kind.template(template)
	if err != nil {
		return nil, err
	}
	return harnessJsonNormal(value)
}

// content brought to hold the template's entries by exact edits, nil edits for one that holds them already; refused
// past a bound on edits, which no real file reaches.
func harnessApplyTemplate(file *harnessFile, content []byte, template *harnessTemplate, ingest *sidecar.SidecarIngestSettings) ([]byte, error) {
	for range ingest.HarnessConfigEditCount {
		edit, err := file.kind.nextEdit(content, template, ingest.HarnessConfigDepthCount)
		if err != nil {
			return nil, err
		}
		if edit == nil {
			return content, nil
		}
		content = harnessApplyEdit(content, edit)
		if int64(len(content)) > ingest.HarnessConfigByteCount {
			return nil, harnessConfigError("past %d bytes", ingest.HarnessConfigByteCount)
		}
	}
	return nil, harnessConfigError("more edits than ur's entries need")
}

// A file's bytes, nil and false for none, refused past HarnessConfigByteCount.
func harnessReadFile(path string, ingest *sidecar.SidecarIngestSettings) ([]byte, os.FileMode, bool, error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, 0, false, nil
	}
	if err != nil {
		return nil, 0, false, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, 0, false, err
	}
	if !info.Mode().IsRegular() {
		return nil, 0, false, harnessConfigError("not a regular file")
	}
	content, err := io.ReadAll(io.LimitReader(file, ingest.HarnessConfigByteCount+1))
	if err != nil {
		return nil, 0, false, err
	}
	if int64(len(content)) > ingest.HarnessConfigByteCount {
		return nil, 0, false, harnessConfigError("past %d bytes", ingest.HarnessConfigByteCount)
	}
	return content, info.Mode().Perm(), true, nil
}

// One file of a plan: its bytes before and after.
type HarnessFilePlan struct {
	Path    string
	Existed bool
	Before  []byte
	After   []byte
	// The file's mode after: an existing file's kept.
	Mode os.FileMode
	// Whether the seal covers it: every harness file, not `.ur`.
	sealed bool
	file   *harnessFile
}

// Whether the plan changes the file.
func (self *HarnessFilePlan) Changed() bool {
	return !self.Existed || !bytes.Equal(self.Before, self.After)
}

// An install planned: each file's edit and the seal it writes.
type HarnessInstallPlan struct {
	args     *HarnessInstallArgs
	template *harnessTemplate
	Files    []*HarnessFilePlan
	Seal     *HarnessSeal
}

// Plans an install: each file read, the template's entries brought into it by exact edits, and the seal of the
// template. Writes nothing.
func PlanHarnessInstall(args *HarnessInstallArgs) (*HarnessInstallPlan, error) {
	adapter, ok := harnessInstallAdapters[args.Harness]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrHarnessUnknown, args.Harness)
	}
	if !filepath.IsAbs(args.UrPath) {
		return nil, errors.New("ur's path is not absolute: every command names it whole (§4.10)")
	}
	if args.Agent != "" {
		if _, err := sidecar.ParseSidecarAgent(args.Agent); err != nil {
			return nil, err
		}
	}
	if args.ProjectDirectory != "" && !filepath.IsAbs(args.ProjectDirectory) {
		return nil, errors.New("the project's directory is not absolute")
	}
	template := newHarnessTemplate(args.Harness, args.UrPath, args.Agent, args.Instance, McpOutwardToolNames(), args.Ingest)
	plan := &HarnessInstallPlan{args: args, template: template}
	for _, file := range adapter.files(args.Home, args.ProjectDirectory) {
		filePlan, err := planHarnessFile(file, template, args.Ingest)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", file.path, err)
		}
		filePlan.sealed = true
		plan.Files = append(plan.Files, filePlan)
	}
	if args.ProjectDirectory != "" {
		projectFile, err := planHarnessProjectFile(args)
		if err != nil {
			return nil, err
		}
		if projectFile != nil {
			plan.Files = append(plan.Files, projectFile)
		}
	}
	seal, err := newHarnessSeal(args, template, adapter)
	if err != nil {
		return nil, err
	}
	plan.Seal = seal
	return plan, nil
}

// One harness file's plan from its bytes now.
func planHarnessFile(file *harnessFile, template *harnessTemplate, ingest *sidecar.SidecarIngestSettings) (*HarnessFilePlan, error) {
	before, mode, existed, err := harnessReadFile(file.path, ingest)
	if err != nil {
		return nil, err
	}
	after, err := harnessApplyTemplate(file, before, template, ingest)
	if err != nil {
		return nil, err
	}
	if !existed {
		mode = file.mode
	}
	return &HarnessFilePlan{Path: file.path, Existed: existed, Before: before, After: after, Mode: mode, file: file}, nil
}

// §5.8's `.ur` for a project install where none is: the agent, when one is named, so the project's sessions act as it.
// An existing `.ur` is the project's and stays as it is; nil then.
func planHarnessProjectFile(args *HarnessInstallArgs) (*HarnessFilePlan, error) {
	path := filepath.Join(args.ProjectDirectory, ".ur")
	_, _, existed, err := harnessReadFile(path, args.Ingest)
	if err != nil {
		return nil, err
	}
	if existed {
		return nil, nil
	}
	content := "# ur's project file (§5.8): the network and agent this project's sessions act as, safe to commit\n"
	if args.Agent != "" {
		content += "agent = " + harnessTomlString(args.Agent) + "\n"
	}
	if _, err := sidecar.ParseSidecarProject([]byte(content)); err != nil {
		return nil, err
	}
	return &HarnessFilePlan{Path: path, After: []byte(content), Mode: harnessFileMode(args.ProjectDirectory)}, nil
}

// Whether the plan changes anything: a file or the seal.
func (self *HarnessInstallPlan) Changed() (bool, error) {
	for _, file := range self.Files {
		if file.Changed() {
			return true, nil
		}
	}
	sealed, err := readHarnessSeal(self.Seal.path(self.args.StateDirectory), self.args.Ingest.HarnessConfigByteCount)
	if err != nil {
		return true, nil
	}
	return !self.Seal.equal(sealed), nil
}

// Every changed file's unified diff, with Ingest.HarnessDiffContextLineCount lines of context, its paths whole.
func (self *HarnessInstallPlan) Diff() string {
	diff := strings.Builder{}
	for _, file := range self.Files {
		if !file.Changed() {
			continue
		}
		before := "a" + filepath.ToSlash(file.Path)
		if !file.Existed {
			before = "/dev/null"
		}
		diff.WriteString(harnessUnifiedDiff(before, "b"+filepath.ToSlash(file.Path), file.Before, file.After, self.args.Ingest.HarnessDiffContextLineCount))
	}
	return diff.String()
}

// Writes every changed file, each by a temporary file renamed over it, then the seal. A file the harness rewrote
// since the plan is planned again from its new bytes, up to Ingest.HarnessInstallRetryCount times.
func (self *HarnessInstallPlan) Write() error {
	for _, file := range self.Files {
		if err := self.writeFile(file); err != nil {
			return fmt.Errorf("%s: %w", file.Path, err)
		}
	}
	return writeHarnessSeal(self.args.StateDirectory, self.Seal)
}

// One file's write.
func (self *HarnessInstallPlan) writeFile(file *HarnessFilePlan) error {
	if !file.Changed() {
		return nil
	}
	ingest := self.args.Ingest
	current := file
	for range max(1, ingest.HarnessInstallRetryCount) {
		now, _, existed, err := harnessReadFile(current.Path, ingest)
		if err != nil {
			return err
		}
		if existed == current.Existed && bytes.Equal(now, current.Before) {
			return harnessWriteFile(current.Path, current.After, current.Mode, self.args.ProjectDirectory == "")
		}
		if current.file == nil {
			// a `.ur` that appeared since the plan is the project's: left as it is
			return nil
		}
		replanned, err := planHarnessFile(current.file, self.template, ingest)
		if err != nil {
			return err
		}
		replanned.sealed = current.sealed
		current = replanned
	}
	return errors.New("the harness kept rewriting the file: run ur install-harness again")
}

// Writes content to path by a temporary file in its directory, synced and renamed over it, the directory made where
// missing, private ones for a user install.
func harnessWriteFile(path string, content []byte, mode os.FileMode, private bool) error {
	directory := filepath.Dir(path)
	directoryMode := os.FileMode(0o755)
	if private {
		directoryMode = 0o700
	}
	if err := os.MkdirAll(directory, directoryMode); err != nil {
		return err
	}
	suffix := make([]byte, 8)
	rand.Read(suffix)
	temporaryPath := filepath.Join(directory, "."+filepath.Base(path)+".ur-install-"+hex.EncodeToString(suffix))
	temporary, err := os.OpenFile(temporaryPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			temporary.Close()
			os.Remove(temporaryPath)
		}
	}()
	if _, err := temporary.Write(content); err != nil {
		return err
	}
	if err := temporary.Chmod(mode); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	committed = true
	// the rename's own durability, where the platform syncs a directory
	if handle, err := os.Open(directory); err == nil {
		handle.Sync()
		handle.Close()
	}
	return nil
}

// A unified diff of before and after, context lines of context, or "" for none. The common head and tail are set
// aside first, so a large file's diff costs only its changed middle.
func harnessUnifiedDiff(beforeName string, afterName string, before []byte, after []byte, context int) string {
	if bytes.Equal(before, after) {
		return ""
	}
	beforeLines := harnessDiffLines(before)
	afterLines := harnessDiffLines(after)
	head := 0
	for head < len(beforeLines) && head < len(afterLines) && beforeLines[head] == afterLines[head] {
		head += 1
	}
	tail := 0
	for tail < len(beforeLines)-head && tail < len(afterLines)-head &&
		beforeLines[len(beforeLines)-1-tail] == afterLines[len(afterLines)-1-tail] {
		tail += 1
	}
	middleBefore := beforeLines[head : len(beforeLines)-tail]
	middleAfter := afterLines[head : len(afterLines)-tail]

	// the middle's longest common subsequence, by lengths from the end
	lengths := make([][]int, len(middleBefore)+1)
	for i := range lengths {
		lengths[i] = make([]int, len(middleAfter)+1)
	}
	for i := len(middleBefore) - 1; 0 <= i; i -= 1 {
		for j := len(middleAfter) - 1; 0 <= j; j -= 1 {
			if middleBefore[i] == middleAfter[j] {
				lengths[i][j] = lengths[i+1][j+1] + 1
			} else {
				lengths[i][j] = max(lengths[i+1][j], lengths[i][j+1])
			}
		}
	}
	type diffLine struct {
		op     byte
		text   string
		before int
		after  int
	}
	lines := []diffLine{}
	for i := range head {
		lines = append(lines, diffLine{op: ' ', text: beforeLines[i], before: i, after: i})
	}
	i, j := 0, 0
	for i < len(middleBefore) || j < len(middleAfter) {
		switch {
		case i < len(middleBefore) && j < len(middleAfter) && middleBefore[i] == middleAfter[j]:
			lines = append(lines, diffLine{op: ' ', text: middleBefore[i], before: head + i, after: head + j})
			i, j = i+1, j+1
		case i < len(middleBefore) && (j == len(middleAfter) || lengths[i+1][j] >= lengths[i][j+1]):
			// a removal before an addition, as diff shows them
			lines = append(lines, diffLine{op: '-', text: middleBefore[i], before: head + i, after: head + j})
			i += 1
		default:
			lines = append(lines, diffLine{op: '+', text: middleAfter[j], before: head + i, after: head + j})
			j += 1
		}
	}
	for k := range tail {
		lines = append(lines, diffLine{op: ' ', text: beforeLines[len(beforeLines)-tail+k],
			before: len(beforeLines) - tail + k, after: len(afterLines) - tail + k})
	}

	diff := strings.Builder{}
	fmt.Fprintf(&diff, "--- %s\n+++ %s\n", beforeName, afterName)
	for start := 0; start < len(lines); {
		if lines[start].op == ' ' {
			start += 1
			continue
		}
		// a hunk: from context lines before the first change to context lines past the last change within reach
		first := max(0, start-context)
		end := start
		for k := start; k < len(lines); k += 1 {
			if lines[k].op != ' ' {
				end = k
			} else if context*2 < k-end {
				break
			}
		}
		last := min(len(lines)-1, end+context)
		beforeCount, afterCount := 0, 0
		for _, line := range lines[first : last+1] {
			if line.op != '+' {
				beforeCount += 1
			}
			if line.op != '-' {
				afterCount += 1
			}
		}
		beforeStart := lines[first].before + 1
		afterStart := lines[first].after + 1
		if beforeCount == 0 {
			beforeStart -= 1
		}
		if afterCount == 0 {
			afterStart -= 1
		}
		fmt.Fprintf(&diff, "@@ -%d,%d +%d,%d @@\n", beforeStart, beforeCount, afterStart, afterCount)
		for _, line := range lines[first : last+1] {
			diff.WriteByte(line.op)
			diff.WriteString(line.text)
			diff.WriteByte('\n')
		}
		start = last + 1
	}
	return diff.String()
}

// content's lines, a final line without its newline marked as such.
func harnessDiffLines(content []byte) []string {
	if len(content) == 0 {
		return nil
	}
	lines := strings.Split(string(content), "\n")
	if lines[len(lines)-1] == "" {
		return lines[:len(lines)-1]
	}
	lines[len(lines)-1] += "\n\\ No newline at end of file"
	return lines
}
