//go:build !ios_extension && !sidecar_http && !js

// Pi's file tools in the local profile (DESIGN-COMPUTE §7.5, R-HARN-4, IC-7): read, write, edit and ls, with Pi
// 1.5.0's names, arguments and texts, since models are trained on them, working only in the agent's workspace
// (harness_workspace.go). grep and find are harness_tool_grep.go's. Each is built in and serves the local profile alone;
// the enclave profile's file tools, which open beneath the agents' container's root, are HARN-M14-05's.
//
//   - read returns a file's lines from offset, at most HarnessSettings.ReadLineCount of them and OutputByteCount bytes,
//     with Pi's notices for what remains. It streams the file, so a large one is never held whole.
//   - write writes a file whole, making its parents, checked against the workspace's cap before it lands.
//   - edit replaces each edits[].oldText, which must match the file exactly and once, edits never overlapping, as
//     Pi's are matched (its legacy oldText and newText, an edits array sent as a string and a single edit object are
//     read as Pi reads them); a match that is not exact and unique is refused, nothing written.
//   - ls lists a directory, dotfiles included, sorted without case, a directory marked with a trailing slash.
//
// A .git component of any spelling is neither read, written, edited nor listed. Nothing here starts a process or
// opens a socket (IC-7).

package sidecar

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"slices"
	"strings"
)

// Each tool's description, Pi 1.5.0's, its paths the workspace's.
const (
	harnessReadDescription = "Read the contents of a file in your workspace. For text files, output is truncated to " +
		"2000 lines or 50KB (whichever is hit first). Use offset/limit for large files. When you need the full file, " +
		"continue with offset until complete."
	harnessWriteDescription = "Write content to a file in your workspace. Creates the file if it doesn't exist, " +
		"overwrites if it does. Automatically creates parent directories."
	harnessEditDescription = "Edit a single file in your workspace using exact text replacement. Every edits[].oldText " +
		"must match a unique, non-overlapping region of the original file. If two changes affect the same block or " +
		"nearby lines, merge them into one edit instead of emitting overlapping edits. Do not include large unchanged " +
		"regions just to connect distant changes."
	harnessLsDescription = "List directory contents in your workspace. Returns entries sorted alphabetically, with '/' " +
		"suffix for directories. Includes dotfiles. Output is truncated to 500 entries or 50KB (whichever is hit first)."
)

// Each tool's argument schema, Pi 1.5.0's names and types, its paths relative to the workspace.
const (
	harnessReadSchema  = `{"type":"object","properties":{"path":{"type":"string","description":"Path to the file to read, relative to your workspace"},"offset":{"type":"number","description":"Line number to start reading from (1-indexed)"},"limit":{"type":"number","description":"Maximum number of lines to read"}},"required":["path"]}`
	harnessWriteSchema = `{"type":"object","properties":{"path":{"type":"string","description":"Path to the file to write, relative to your workspace"},"content":{"type":"string","description":"Content to write to the file"}},"required":["path","content"]}`
	harnessEditSchema  = `{"type":"object","properties":{"path":{"type":"string","description":"Path to the file to edit, relative to your workspace"},"edits":{"type":"array","description":"One or more targeted replacements. Each edit is matched against the original file, not incrementally. Do not include overlapping or nested edits. If two changes touch the same block or nearby lines, merge them into one edit instead.","items":{"type":"object","properties":{"oldText":{"type":"string","description":"Exact text for one targeted replacement. It must be unique in the original file and must not overlap with any other edits[].oldText in the same call."},"newText":{"type":"string","description":"Replacement text for this targeted edit."}},"required":["oldText","newText"]}}},"required":["path","edits"]}`
	harnessLsSchema    = `{"type":"object","properties":{"path":{"type":"string","description":"Directory to list (default: your workspace)"},"limit":{"type":"number","description":"Maximum number of entries to return (default: 500)"}}}`
)

// Registers read, write, edit and ls for the local profile, built in.
func init() {
	for _, tool := range []struct {
		name string
		new  func(harness *Harness) HarnessTool
	}{
		{name: "read", new: func(harness *Harness) HarnessTool { return &harnessReadTool{settings: harness.settings} }},
		{name: "write", new: func(harness *Harness) HarnessTool { return &harnessWriteTool{} }},
		{name: "edit", new: func(harness *Harness) HarnessTool { return &harnessEditTool{} }},
		{name: "ls", new: func(harness *Harness) HarnessTool { return &harnessLsTool{settings: harness.settings} }},
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

// The workspace of the call ctx carries, or an error where it has none: no file tool runs outside one.
func harnessCallWorkspace(ctx context.Context) (*harnessWorkspace, error) {
	call, ok := HarnessCallFromContext(ctx)
	if !ok || call.workspace == nil {
		return nil, errors.New("this run has no workspace")
	}
	return call.workspace, nil
}

// Pi's formatSize: bytes, KB or MB to one place.
func harnessFormatSize(byteCount int) string {
	switch {
	case byteCount < 1024:
		return fmt.Sprintf("%dB", byteCount)
	case byteCount < 1024*1024:
		return fmt.Sprintf("%.1fKB", float64(byteCount)/1024)
	}
	return fmt.Sprintf("%.1fMB", float64(byteCount)/(1024*1024))
}

// Pi's truncateHead over lines already split: the lines that fit maxLines and maxBytes, never a partial one, and
// whether the first alone passes maxBytes.
type harnessTruncation struct {
	lines                 []string
	truncated             bool
	truncatedByBytes      bool
	firstLineExceedsLimit bool
}

// lines truncated as Pi's truncateHead does.
func harnessTruncateHead(lines []string, maxLines int, maxBytes int) *harnessTruncation {
	totalBytes := 0
	for i, line := range lines {
		totalBytes += len(line)
		if 0 < i {
			totalBytes += 1
		}
	}
	if len(lines) <= maxLines && totalBytes <= maxBytes {
		return &harnessTruncation{lines: lines}
	}
	if 0 < len(lines) && maxBytes < len(lines[0]) {
		return &harnessTruncation{truncated: true, truncatedByBytes: true, firstLineExceedsLimit: true}
	}
	kept := []string{}
	byteCount := 0
	byBytes := false
	for i := 0; i < len(lines) && i < maxLines; i += 1 {
		lineBytes := len(lines[i])
		if 0 < i {
			lineBytes += 1
		}
		if maxBytes < byteCount+lineBytes {
			byBytes = true
			break
		}
		kept = append(kept, lines[i])
		byteCount += lineBytes
	}
	return &harnessTruncation{lines: kept, truncated: true, truncatedByBytes: byBytes}
}

// read's arguments.
type harnessReadArgs struct {
	Path   string   `json:"path"`
	Offset *float64 `json:"offset"`
	Limit  *float64 `json:"limit"`
}

// Pi's read.
type harnessReadTool struct {
	settings *HarnessSettings
}

// read.
func (self *harnessReadTool) Name() string {
	return "read"
}

// Pi's description, its paths the workspace's.
func (self *harnessReadTool) Description() string {
	return harnessReadDescription
}

// Pi's arguments.
func (self *harnessReadTool) Schema() []byte {
	return []byte(harnessReadSchema)
}

// Reads run beside each other.
func (self *harnessReadTool) Mode() string {
	return HarnessToolParallel
}

// A read.
func (self *harnessReadTool) Tier() string {
	return HarnessToolTierRead
}

// Reads the file's lines from offset, as Pi's read does, streaming it.
func (self *harnessReadTool) Execute(ctx context.Context, callId string, args []byte, update func(*HarnessToolUpdate)) (*HarnessToolResult, error) {
	read := &harnessReadArgs{}
	if err := harnessToolArgs(args, read); err != nil {
		return nil, err
	}
	workspace, err := harnessCallWorkspace(ctx)
	if err != nil {
		return nil, err
	}
	file, held, err := workspace.Open(read.Path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if info, err := file.Stat(); err == nil && info.IsDir() {
		return nil, fmt.Errorf("%s is a directory", held)
	}
	startLine := 0
	if read.Offset != nil && 1 < *read.Offset {
		startLine = int(*read.Offset) - 1
	}
	limitLines := -1
	if read.Limit != nil {
		limitLines = max(0, int(*read.Limit))
	}
	// stream the file: count every line as Pi's split does, keep what read returns and no more
	maxLines, maxBytes := self.settings.ReadLineCount, self.settings.OutputByteCount
	reader := bufio.NewReader(file)
	totalLines := 0
	selectedCount := 0
	kept := []string{}
	keptBytes := 0
	stoppedByLines, stoppedByBytes, firstTooLong := false, false, false
	for {
		text, eof, err := harnessReadLine(reader, maxBytes+1)
		if err != nil {
			return nil, harnessWorkspaceError(err)
		}
		lineIndex := totalLines
		totalLines += 1
		switch {
		case lineIndex < startLine, 0 <= limitLines && limitLines <= selectedCount:
		default:
			selectedCount += 1
			if stoppedByLines || stoppedByBytes {
				break
			}
			if maxLines <= len(kept) {
				stoppedByLines = true
				break
			}
			lineBytes := len(text)
			if 0 < len(kept) {
				lineBytes += 1
			}
			if maxBytes < keptBytes+lineBytes {
				firstTooLong = len(kept) == 0
				stoppedByBytes = true
				break
			}
			kept = append(kept, text)
			keptBytes += lineBytes
		}
		if eof {
			break
		}
	}
	if totalLines <= startLine {
		return nil, fmt.Errorf("Offset %d is beyond end of file (%d lines total)", startLine+1, totalLines)
	}
	startLineDisplay := startLine + 1
	text := ""
	switch {
	case firstTooLong:
		text = fmt.Sprintf("[Line %d is longer than %s. It is not shown.]", startLineDisplay, harnessFormatSize(maxBytes))
	case stoppedByLines || stoppedByBytes:
		endLineDisplay := startLineDisplay + len(kept) - 1
		text = strings.Join(kept, "\n")
		if stoppedByBytes {
			text += fmt.Sprintf("\n\n[Showing lines %d-%d of %d (%s limit). Use offset=%d to continue.]", startLineDisplay,
				endLineDisplay, totalLines, harnessFormatSize(maxBytes), endLineDisplay+1)
		} else {
			text += fmt.Sprintf("\n\n[Showing lines %d-%d of %d. Use offset=%d to continue.]", startLineDisplay,
				endLineDisplay, totalLines, endLineDisplay+1)
		}
	case 0 <= limitLines && startLine+selectedCount < totalLines:
		remaining := totalLines - (startLine + selectedCount)
		text = fmt.Sprintf("%s\n\n[%d more lines in file. Use offset=%d to continue.]", strings.Join(kept, "\n"),
			remaining, startLine+selectedCount+1)
	default:
		text = strings.Join(kept, "\n")
	}
	return &HarnessToolResult{Text: text, Trust: HarnessToolTrusted}, nil
}

// One line of reader, as Pi's split on newline gives it, keeping at most keep bytes of it and reading past the rest,
// so a long line is never held whole; eof once the line is the last.
func harnessReadLine(reader *bufio.Reader, keep int) (string, bool, error) {
	line := []byte{}
	for {
		chunk, err := reader.ReadSlice('\n')
		if room := keep - len(line); 0 < room {
			line = append(line, chunk[:min(room, len(chunk))]...)
		}
		switch {
		case err == nil:
			return strings.TrimSuffix(string(line), "\n"), false, nil
		case err == io.EOF:
			return string(line), true, nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		}
		return "", false, err
	}
}

// write's arguments.
type harnessWriteArgs struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// Pi's write.
type harnessWriteTool struct{}

// write.
func (self *harnessWriteTool) Name() string {
	return "write"
}

// Pi's description, its paths the workspace's.
func (self *harnessWriteTool) Description() string {
	return harnessWriteDescription
}

// Pi's arguments.
func (self *harnessWriteTool) Schema() []byte {
	return []byte(harnessWriteSchema)
}

// Writes run beside each other, each path's in order through the workspace's mutation queue.
func (self *harnessWriteTool) Mode() string {
	return HarnessToolParallel
}

// A write inside the workspace, which leaves the device only through git push or evs_write.
func (self *harnessWriteTool) Tier() string {
	return HarnessToolTierWrite
}

// Writes the file whole, as Pi's write does.
func (self *harnessWriteTool) Execute(ctx context.Context, callId string, args []byte, update func(*HarnessToolUpdate)) (*HarnessToolResult, error) {
	write := &harnessWriteArgs{}
	if err := harnessToolArgs(args, write); err != nil {
		return nil, err
	}
	workspace, err := harnessCallWorkspace(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := workspace.WriteFile(write.Path, []byte(write.Content)); err != nil {
		return nil, err
	}
	return &HarnessToolResult{Text: "Successfully wrote to " + write.Path, Trust: HarnessToolTrusted}, nil
}

// One replacement.
type harnessEditReplacement struct {
	OldText string `json:"oldText"`
	NewText string `json:"newText"`
}

// edit's arguments, read as Pi's prepareEditArguments does: edits as an array, a JSON string holding one, or a single
// edit object, and the legacy oldText and newText appended.
type harnessEditArgs struct {
	Path  string
	Edits []*harnessEditReplacement
}

// The arguments of an edit call.
func harnessParseEditArgs(args []byte) (*harnessEditArgs, error) {
	raw := struct {
		Path    string          `json:"path"`
		Edits   json.RawMessage `json:"edits"`
		OldText *string         `json:"oldText"`
		NewText *string         `json:"newText"`
	}{}
	if err := harnessToolArgs(args, &raw); err != nil {
		return nil, err
	}
	parsed := &harnessEditArgs{Path: raw.Path}
	edits := raw.Edits
	text := ""
	if json.Unmarshal(edits, &text) == nil {
		edits = json.RawMessage(text)
	}
	if 0 < len(edits) {
		list := []*harnessEditReplacement{}
		if json.Unmarshal(edits, &list) != nil {
			single := &harnessEditReplacement{}
			if json.Unmarshal(edits, single) != nil {
				return nil, errors.New("Edit tool input is invalid. edits must contain at least one replacement.")
			}
			list = []*harnessEditReplacement{single}
		}
		parsed.Edits = list
	}
	if raw.OldText != nil && raw.NewText != nil {
		parsed.Edits = append(parsed.Edits, &harnessEditReplacement{OldText: *raw.OldText, NewText: *raw.NewText})
	}
	if len(parsed.Edits) == 0 {
		return nil, errors.New("Edit tool input is invalid. edits must contain at least one replacement.")
	}
	return parsed, nil
}

// A matched replacement.
type harnessEditMatch struct {
	editIndex int
	at        int
	length    int
	newText   string
}

// content with edits applied, each matched exactly and once against content as it was, never overlapping, refused
// with Pi's errors otherwise (edit-diff.js's applyEditsToNormalizedContent without its fuzzy fallback).
func harnessApplyEdits(content string, edits []*harnessEditReplacement, path string) (string, error) {
	total := len(edits)
	label := func(index int) string {
		if total == 1 {
			return "the text"
		}
		return fmt.Sprintf("edits[%d]", index)
	}
	matches := []*harnessEditMatch{}
	for i, edit := range edits {
		oldText := strings.ReplaceAll(strings.ReplaceAll(edit.OldText, "\r\n", "\n"), "\r", "\n")
		newText := strings.ReplaceAll(strings.ReplaceAll(edit.NewText, "\r\n", "\n"), "\r", "\n")
		if oldText == "" {
			if total == 1 {
				return "", fmt.Errorf("oldText must not be empty in %s.", path)
			}
			return "", fmt.Errorf("edits[%d].oldText must not be empty in %s.", i, path)
		}
		count := strings.Count(content, oldText)
		switch {
		case count == 0 && total == 1:
			return "", fmt.Errorf("Could not find the exact text in %s. The old text must match exactly including all whitespace and newlines.", path)
		case count == 0:
			return "", fmt.Errorf("Could not find edits[%d] in %s. The oldText must match exactly including all whitespace and newlines.", i, path)
		case 1 < count && total == 1:
			return "", fmt.Errorf("Found %d occurrences of the text in %s. The text must be unique. Please provide more context to make it unique.", count, path)
		case 1 < count:
			return "", fmt.Errorf("Found %d occurrences of %s in %s. Each oldText must be unique. Please provide more context to make it unique.", count, label(i), path)
		}
		matches = append(matches, &harnessEditMatch{editIndex: i, at: strings.Index(content, oldText), length: len(oldText), newText: newText})
	}
	slices.SortFunc(matches, func(a *harnessEditMatch, b *harnessEditMatch) int { return a.at - b.at })
	for i := 1; i < len(matches); i += 1 {
		previous, current := matches[i-1], matches[i]
		if current.at < previous.at+previous.length {
			return "", fmt.Errorf("edits[%d] and edits[%d] overlap in %s. Merge them into one edit or target disjoint regions.",
				previous.editIndex, current.editIndex, path)
		}
	}
	builder := strings.Builder{}
	last := 0
	for _, match := range matches {
		builder.WriteString(content[last:match.at])
		builder.WriteString(match.newText)
		last = match.at + match.length
	}
	builder.WriteString(content[last:])
	edited := builder.String()
	if edited == content {
		if total == 1 {
			return "", fmt.Errorf("No changes made to %s. The replacement produced identical content. This might indicate an issue with special characters or the text not existing as expected.", path)
		}
		return "", fmt.Errorf("No changes made to %s. The replacements produced identical content.", path)
	}
	return edited, nil
}

// A line diff of before and after for the edit card: each changed line, its number, - for before and + for after,
// and the first changed line.
func harnessEditDiff(before string, after string) (string, int) {
	beforeLines := strings.Split(before, "\n")
	afterLines := strings.Split(after, "\n")
	head := 0
	for head < len(beforeLines) && head < len(afterLines) && beforeLines[head] == afterLines[head] {
		head += 1
	}
	tail := 0
	for tail < len(beforeLines)-head && tail < len(afterLines)-head &&
		beforeLines[len(beforeLines)-1-tail] == afterLines[len(afterLines)-1-tail] {
		tail += 1
	}
	lines := []string{}
	for i := head; i < len(beforeLines)-tail; i += 1 {
		lines = append(lines, fmt.Sprintf("-%d %s", i+1, beforeLines[i]))
	}
	for i := head; i < len(afterLines)-tail; i += 1 {
		lines = append(lines, fmt.Sprintf("+%d %s", i+1, afterLines[i]))
	}
	return strings.Join(lines, "\n"), head + 1
}

// Pi's edit.
type harnessEditTool struct{}

// edit.
func (self *harnessEditTool) Name() string {
	return "edit"
}

// Pi's description, its paths the workspace's.
func (self *harnessEditTool) Description() string {
	return harnessEditDescription
}

// Pi's arguments.
func (self *harnessEditTool) Schema() []byte {
	return []byte(harnessEditSchema)
}

// Edits run beside each other, each path's in order through the workspace's mutation queue.
func (self *harnessEditTool) Mode() string {
	return HarnessToolParallel
}

// A write inside the workspace.
func (self *harnessEditTool) Tier() string {
	return HarnessToolTierWrite
}

// Applies the edits as Pi's edit does: the file's BOM kept aside, its line endings read, matched over LF, written back
// with its endings, through the path's mutation queue and the cap.
func (self *harnessEditTool) Execute(ctx context.Context, callId string, args []byte, update func(*HarnessToolUpdate)) (*HarnessToolResult, error) {
	edit, err := harnessParseEditArgs(args)
	if err != nil {
		return nil, err
	}
	workspace, err := harnessCallWorkspace(ctx)
	if err != nil {
		return nil, err
	}
	held, err := harnessWorkspacePath(edit.Path)
	if err != nil {
		return nil, err
	}
	var details []byte
	err = workspace.withMutation(held, func() error {
		data, _, err := workspace.ReadFile(held, workspace.CapByteCount())
		if err != nil {
			return fmt.Errorf("Could not edit file: %s. %v.", edit.Path, err)
		}
		raw := string(data)
		bom := ""
		if strings.HasPrefix(raw, "\uFEFF") {
			bom = "\uFEFF"
			raw = strings.TrimPrefix(raw, bom)
		}
		crlf := false
		if lf := strings.Index(raw, "\n"); 0 <= lf && 0 < lf && raw[lf-1] == '\r' {
			crlf = true
		}
		normalized := strings.ReplaceAll(strings.ReplaceAll(raw, "\r\n", "\n"), "\r", "\n")
		edited, err := harnessApplyEdits(normalized, edit.Edits, edit.Path)
		if err != nil {
			return err
		}
		written := edited
		if crlf {
			written = strings.ReplaceAll(edited, "\n", "\r\n")
		}
		if err := workspace.writeWithMutation(held, []byte(bom+written)); err != nil {
			return err
		}
		diff, firstChangedLine := harnessEditDiff(normalized, edited)
		details, _ = harnessPiMarshal(map[string]any{"diff": diff, "firstChangedLine": firstChangedLine})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &HarnessToolResult{
		Text:    fmt.Sprintf("Successfully replaced %d block(s) in %s.", len(edit.Edits), edit.Path),
		Details: details,
		Trust:   HarnessToolTrusted,
	}, nil
}

// ls's arguments.
type harnessLsArgs struct {
	Path  string   `json:"path"`
	Limit *float64 `json:"limit"`
}

// Pi's ls.
type harnessLsTool struct {
	settings *HarnessSettings
}

// ls.
func (self *harnessLsTool) Name() string {
	return "ls"
}

// Pi's description, its paths the workspace's.
func (self *harnessLsTool) Description() string {
	return harnessLsDescription
}

// Pi's arguments.
func (self *harnessLsTool) Schema() []byte {
	return []byte(harnessLsSchema)
}

// Listings run beside each other.
func (self *harnessLsTool) Mode() string {
	return HarnessToolParallel
}

// A read.
func (self *harnessLsTool) Tier() string {
	return HarnessToolTierRead
}

// Lists the directory as Pi's ls does, leaving out every .git spelling.
func (self *harnessLsTool) Execute(ctx context.Context, callId string, args []byte, update func(*HarnessToolUpdate)) (*HarnessToolResult, error) {
	ls := &harnessLsArgs{}
	if err := harnessToolArgs(args, ls); err != nil {
		return nil, err
	}
	workspace, err := harnessCallWorkspace(ctx)
	if err != nil {
		return nil, err
	}
	name := ls.Path
	if name == "" {
		name = "."
	}
	info, held, err := workspace.Stat(name)
	if err != nil {
		return nil, fmt.Errorf("Path not found: %s", name)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("Not a directory: %s", held)
	}
	entries, _, err := workspace.ReadDir(held)
	if err != nil {
		return nil, fmt.Errorf("Cannot read directory: %v", err)
	}
	limit := self.settings.LsEntryCount
	if ls.Limit != nil {
		limit = max(0, int(*ls.Limit))
	}
	slices.SortFunc(entries, func(a fs.DirEntry, b fs.DirEntry) int {
		return strings.Compare(strings.ToLower(a.Name()), strings.ToLower(b.Name()))
	})
	results := []string{}
	limitReached := false
	for _, entry := range entries {
		if harnessGitPathComponent(entry.Name()) {
			continue
		}
		if limit <= len(results) {
			limitReached = true
			break
		}
		child := entry.Name()
		if held != "." {
			child = held + "/" + entry.Name()
		}
		childInfo, _, err := workspace.Stat(child)
		if err != nil {
			// an entry it cannot stat, a link out among them, is skipped as Pi skips it
			continue
		}
		suffix := ""
		if childInfo.IsDir() {
			suffix = "/"
		}
		results = append(results, entry.Name()+suffix)
	}
	if len(results) == 0 {
		return &HarnessToolResult{Text: "(empty directory)", Trust: HarnessToolTrusted}, nil
	}
	truncation := harnessTruncateHead(strings.Split(strings.Join(results, "\n"), "\n"), len(results), self.settings.OutputByteCount)
	text := strings.Join(truncation.lines, "\n")
	notices := []string{}
	if limitReached {
		notices = append(notices, fmt.Sprintf("%d entries limit reached. Use limit=%d for more", limit, limit*2))
	}
	if truncation.truncated {
		notices = append(notices, fmt.Sprintf("%s limit reached", harnessFormatSize(self.settings.OutputByteCount)))
	}
	if 0 < len(notices) {
		text += "\n\n[" + strings.Join(notices, ". ") + "]"
	}
	return &HarnessToolResult{Text: text, Trust: HarnessToolTrusted}, nil
}
