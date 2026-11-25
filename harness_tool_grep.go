//go:build !ios_extension && !sidecar_http && !js

// Pi's grep and find in the local profile (DESIGN-COMPUTE §7.5, IC-7): Pi 1.5.0's names, arguments and output, in Go
// over the agent's workspace, never rg or fd, so nothing starts a process (CO-6). Both walk the workspace in name
// order, leave out every .git spelling, and stay inside the workspace: a link resolving outside is not followed.
//
//   - grep matches each line of each file against the pattern (Go's RE2, which reads ripgrep's common syntax; literal
//     quotes it; ignoreCase folds case), a glob narrowing the files, context lines around each match, at most limit
//     matches (HarnessSettings.GrepMatchCount where none is named), each line cut to GrepLineCharCount characters,
//     the output to OutputByteCount bytes, with Pi's notices. A file larger than GrepFileByteCount, or one holding a
//     NUL in its first GrepBinaryProbeByteCount bytes, as ripgrep skips binary files, is not searched.
//   - find lists the paths beneath the search directory that match a glob, a pattern without a slash matching each
//     name and one with a slash the whole relative path, ** spanning directories, at most limit of them
//     (FindResultCount where none is named), a directory with a trailing slash.
//
// Unlike Pi's, neither reads .gitignore files yet: a worktree's ignored files are searched and listed.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Each tool's description, Pi 1.5.0's, its paths the workspace's.
const (
	harnessGrepDescription = "Search file contents in your workspace for a pattern. Returns matching lines with file " +
		"paths and line numbers. Output is truncated to 100 matches or 50KB (whichever is hit first). Long lines are " +
		"truncated to 500 chars."
	harnessFindDescription = "Search for files in your workspace by glob pattern. Returns matching file paths " +
		"relative to the search directory. Output is truncated to 1000 results or 50KB (whichever is hit first)."
)

// Each tool's argument schema, Pi 1.5.0's names and types.
const (
	harnessGrepSchema = `{"type":"object","properties":{"pattern":{"type":"string","description":"Search pattern (regex or literal string)"},"path":{"type":"string","description":"Directory or file to search (default: your workspace)"},"glob":{"type":"string","description":"Filter files by glob pattern, e.g. '*.ts' or '**/*.spec.ts'"},"ignoreCase":{"type":"boolean","description":"Case-insensitive search (default: false)"},"literal":{"type":"boolean","description":"Treat pattern as literal string instead of regex (default: false)"},"context":{"type":"number","description":"Number of lines to show before and after each match (default: 0)"},"limit":{"type":"number","description":"Maximum number of matches to return (default: 100)"}},"required":["pattern"]}`
	harnessFindSchema = `{"type":"object","properties":{"pattern":{"type":"string","description":"Glob pattern to match files, e.g. '*.ts', '**/*.json', or 'src/**/*.spec.ts'"},"path":{"type":"string","description":"Directory to search in (default: your workspace)"},"limit":{"type":"number","description":"Maximum number of results (default: 1000)"}},"required":["pattern"]}`
)

// Registers grep and find for the local profile, built in.
func init() {
	for _, tool := range []struct {
		name string
		new  func(harness *Harness) HarnessTool
	}{
		{name: "grep", new: func(harness *Harness) HarnessTool { return &harnessGrepTool{settings: harness.settings} }},
		{name: "find", new: func(harness *Harness) HarnessTool { return &harnessFindTool{settings: harness.settings} }},
	} {
		construct := tool.new
		RegisterHarnessTool(&HarnessToolSpec{
			Name:     tool.name,
			Profiles: []HarnessProfile{HarnessProfileLocal},
			BuiltIn:  true,
			New: func(harness *Harness) (HarnessTool, error) {
				if harness == nil || harness.settings == nil {
					return nil, errors.New("a file tool needs the Harness's settings")
				}
				return construct(harness), nil
			},
		})
	}
}

// Whether name, a path relative to the search root with / separators, matches glob: a glob with no slash against the
// last component, one with a slash against the whole path, ** spanning any number of components.
func harnessGlobMatch(glob string, name string) bool {
	glob = strings.TrimPrefix(glob, "./")
	if !strings.Contains(glob, "/") {
		matched, _ := path.Match(glob, path.Base(name))
		return matched
	}
	glob = strings.TrimPrefix(glob, "/")
	return harnessGlobSegments(strings.Split(glob, "/"), strings.Split(name, "/"))
}

// Whether the components of name match those of glob, ** taking zero or more.
func harnessGlobSegments(glob []string, name []string) bool {
	for len(glob) != 0 {
		if glob[0] == "**" && len(glob) == 1 {
			// a trailing ** takes everything inside, not the directory itself
			return 0 < len(name)
		}
		if glob[0] == "**" {
			for skip := 0; skip <= len(name); skip += 1 {
				if harnessGlobSegments(glob[1:], name[skip:]) {
					return true
				}
			}
			return false
		}
		if len(name) == 0 {
			return false
		}
		if matched, _ := path.Match(glob[0], name[0]); !matched {
			return false
		}
		glob, name = glob[1:], name[1:]
	}
	return len(name) == 0
}

// Walks the workspace beneath held in name order, calling visit with each path relative to the workspace, each
// relative to held, and its entry; .git spellings are left out with all they hold, and visit's fs.SkipAll ends the walk.
func harnessWorkspaceWalk(workspace *harnessWorkspace, held string, visit func(name string, relative string, entry fs.DirEntry) error) error {
	return fs.WalkDir(workspace.root.FS(), held, func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			// a path gone, or a link out the root refused, is passed over
			if name == held {
				return err
			}
			return nil
		}
		if name != held && harnessGitPathComponent(entry.Name()) {
			if entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		relative := name
		if held != "." {
			relative = strings.TrimPrefix(strings.TrimPrefix(name, held), "/")
		}
		return visit(name, relative, entry)
	})
}

// grep's arguments.
type harnessGrepArgs struct {
	Pattern    string   `json:"pattern"`
	Path       string   `json:"path"`
	Glob       string   `json:"glob"`
	IgnoreCase bool     `json:"ignoreCase"`
	Literal    bool     `json:"literal"`
	Context    *float64 `json:"context"`
	Limit      *float64 `json:"limit"`
}

// Pi's grep, in Go.
type harnessGrepTool struct {
	settings *HarnessSettings
}

// grep.
func (self *harnessGrepTool) Name() string {
	return "grep"
}

// Pi's description, its paths the workspace's.
func (self *harnessGrepTool) Description() string {
	return harnessGrepDescription
}

// Pi's arguments.
func (self *harnessGrepTool) Schema() []byte {
	return []byte(harnessGrepSchema)
}

// Searches run beside each other.
func (self *harnessGrepTool) Mode() string {
	return HarnessToolParallel
}

// A read.
func (self *harnessGrepTool) Tier() string {
	return HarnessToolTierRead
}

// line cut to the settings' characters, as Pi's truncateLine does.
func (self *harnessGrepTool) cut(line string) (string, bool) {
	if utf8.RuneCountInString(line) <= self.settings.GrepLineCharCount {
		return line, false
	}
	runes := []rune(line)
	return string(runes[:self.settings.GrepLineCharCount]) + "... [truncated]", true
}

// Searches as Pi's grep does, in Go.
func (self *harnessGrepTool) Execute(ctx context.Context, callId string, args []byte, update func(*HarnessToolUpdate)) (*HarnessToolResult, error) {
	grep := &harnessGrepArgs{}
	if err := harnessToolArgs(args, grep); err != nil {
		return nil, err
	}
	workspace, err := harnessCallWorkspace(ctx)
	if err != nil {
		return nil, err
	}
	pattern := grep.Pattern
	if grep.Literal {
		pattern = regexp.QuoteMeta(pattern)
	}
	if grep.IgnoreCase {
		pattern = "(?i)" + pattern
	}
	matcher, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("the pattern does not compile: %v", err)
	}
	searchName := grep.Path
	if searchName == "" {
		searchName = "."
	}
	info, held, err := workspace.Stat(searchName)
	if err != nil {
		return nil, fmt.Errorf("Path not found: %s", searchName)
	}
	contextLines := 0
	if grep.Context != nil && 0 < *grep.Context {
		contextLines = int(*grep.Context)
	}
	limit := self.settings.GrepMatchCount
	if grep.Limit != nil {
		limit = max(1, int(*grep.Limit))
	}

	outputLines := []string{}
	matchCount := 0
	limitReached := false
	linesTruncated := false
	searchFile := func(name string, display string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		fileInfo, _, err := workspace.Stat(name)
		if err != nil || !fileInfo.Mode().IsRegular() || self.settings.GrepFileByteCount < fileInfo.Size() {
			return nil
		}
		file, _, err := workspace.Open(name)
		if err != nil {
			return nil
		}
		data, err := io.ReadAll(io.LimitReader(file, self.settings.GrepFileByteCount))
		file.Close()
		if err != nil || bytes.IndexByte(data[:min(len(data), self.settings.GrepBinaryProbeByteCount)], 0) >= 0 {
			return nil
		}
		lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
		for i, line := range lines {
			if !matcher.MatchString(line) {
				continue
			}
			if limit <= matchCount {
				limitReached = true
				return fs.SkipAll
			}
			matchCount += 1
			start, end := i, i
			if 0 < contextLines {
				start, end = max(0, i-contextLines), min(len(lines)-1, i+contextLines)
			}
			for current := start; current <= end; current += 1 {
				text, cut := self.cut(strings.ReplaceAll(lines[current], "\r", ""))
				linesTruncated = linesTruncated || cut
				if current == i {
					outputLines = append(outputLines, fmt.Sprintf("%s:%d: %s", display, current+1, text))
				} else {
					outputLines = append(outputLines, fmt.Sprintf("%s-%d- %s", display, current+1, text))
				}
			}
		}
		return nil
	}
	if info.IsDir() {
		err = harnessWorkspaceWalk(workspace, held, func(name string, relative string, entry fs.DirEntry) error {
			if entry.IsDir() || (grep.Glob != "" && !harnessGlobMatch(grep.Glob, relative)) {
				return nil
			}
			return searchFile(name, relative)
		})
	} else {
		err = searchFile(held, path.Base(held))
	}
	if err != nil && !errors.Is(err, fs.SkipAll) {
		return nil, harnessWorkspaceError(err)
	}
	if matchCount == 0 {
		return &HarnessToolResult{Text: "No matches found", Trust: HarnessToolTrusted}, nil
	}
	truncation := harnessTruncateHead(outputLines, len(outputLines), self.settings.OutputByteCount)
	text := strings.Join(truncation.lines, "\n")
	notices := []string{}
	if limitReached {
		notices = append(notices, fmt.Sprintf("%d matches limit reached. Use limit=%d for more, or refine pattern", limit, limit*2))
	}
	if truncation.truncated {
		notices = append(notices, fmt.Sprintf("%s limit reached", harnessFormatSize(self.settings.OutputByteCount)))
	}
	if linesTruncated {
		notices = append(notices, fmt.Sprintf("Some lines truncated to %d chars. Use read tool to see full lines", self.settings.GrepLineCharCount))
	}
	if 0 < len(notices) {
		text += "\n\n[" + strings.Join(notices, ". ") + "]"
	}
	return &HarnessToolResult{Text: text, Trust: HarnessToolTrusted}, nil
}

// find's arguments.
type harnessFindArgs struct {
	Pattern string   `json:"pattern"`
	Path    string   `json:"path"`
	Limit   *float64 `json:"limit"`
}

// Pi's find, in Go.
type harnessFindTool struct {
	settings *HarnessSettings
}

// find.
func (self *harnessFindTool) Name() string {
	return "find"
}

// Pi's description, its paths the workspace's.
func (self *harnessFindTool) Description() string {
	return harnessFindDescription
}

// Pi's arguments.
func (self *harnessFindTool) Schema() []byte {
	return []byte(harnessFindSchema)
}

// Finds run beside each other.
func (self *harnessFindTool) Mode() string {
	return HarnessToolParallel
}

// A read.
func (self *harnessFindTool) Tier() string {
	return HarnessToolTierRead
}

// Lists matching paths as Pi's find does, in Go.
func (self *harnessFindTool) Execute(ctx context.Context, callId string, args []byte, update func(*HarnessToolUpdate)) (*HarnessToolResult, error) {
	find := &harnessFindArgs{}
	if err := harnessToolArgs(args, find); err != nil {
		return nil, err
	}
	workspace, err := harnessCallWorkspace(ctx)
	if err != nil {
		return nil, err
	}
	searchName := find.Path
	if searchName == "" {
		searchName = "."
	}
	info, held, err := workspace.Stat(searchName)
	if err != nil || !info.IsDir() {
		return nil, fmt.Errorf("Path not found: %s", searchName)
	}
	limit := self.settings.FindResultCount
	if find.Limit != nil {
		limit = max(1, int(*find.Limit))
	}
	glob := find.Pattern
	if strings.Contains(glob, "/") && !strings.HasPrefix(glob, "/") && !strings.HasPrefix(glob, "**/") && glob != "**" {
		glob = "**/" + glob
	}
	results := []string{}
	err = harnessWorkspaceWalk(workspace, held, func(name string, relative string, entry fs.DirEntry) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if relative == "" || relative == "." || !harnessGlobMatch(glob, relative) {
			return nil
		}
		if limit <= len(results) {
			return fs.SkipAll
		}
		if entry.IsDir() {
			relative += "/"
		}
		results = append(results, relative)
		return nil
	})
	if err != nil && !errors.Is(err, fs.SkipAll) {
		return nil, harnessWorkspaceError(err)
	}
	if len(results) == 0 {
		return &HarnessToolResult{Text: "No files found matching pattern", Trust: HarnessToolTrusted}, nil
	}
	truncation := harnessTruncateHead(results, len(results), self.settings.OutputByteCount)
	text := strings.Join(truncation.lines, "\n")
	notices := []string{}
	if limit <= len(results) {
		notices = append(notices, fmt.Sprintf("%d results limit reached. Use limit=%d for more, or refine pattern", limit, limit*2))
	}
	if truncation.truncated {
		notices = append(notices, fmt.Sprintf("%s limit reached", harnessFormatSize(self.settings.OutputByteCount)))
	}
	if 0 < len(notices) {
		text += "\n\n[" + strings.Join(notices, ". ") + "]"
	}
	return &HarnessToolResult{Text: text, Trust: HarnessToolTrusted}, nil
}
