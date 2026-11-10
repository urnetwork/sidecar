//go:build !js && !ios && !android && !sdk_mobile_bind

// §16.7's before row (D-MCP-15): an edit's before_sha256 is known only from bytes the edit is checked against.
//
//	hold     Claude Code and Codex: at a PreToolUse naming paths, each path's bytes are sealed into the point under
//	         the call's tool_use_id, at most Ingest.RestoreHoldTimeout and Ingest.RestoreHoldByteCount a file, and
//	         `ur hook` acks once they are held (HookHolds)
//	check    at the PostToolUse with that tool_use_id, the hold's bytes are kept as the before only if the call's
//	         input re-applied to them gives the after bytes: Edit's old_string, new_string and replace_all, matched
//	         exactly; MultiEdit's edits in order; Write's content; apply_patch's patch in tool_input.command;
//	         NotebookEdit's cell, the parsed cells equal outside it
//	reverse  Cursor, with no pre-edit event: afterFileEdit's edits reversed on the after bytes, last first, each
//	         new_string found exactly once, else unknown
//	unknown  otherwise: no hold, a timed-out or oversize one, or bytes the input does not reproduce; the edit then
//	         counts as a non-path tool for attribution
//
// A hold's bytes are sealed in the point and read back from it at the check, and its copy is removed once checked or
// timed out. Which calls are held is this process's memory: a restart between the two hooks loses the hold, so that
// edit's before is unknown, and the next process removes the copy when it reads the point.

package mcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
)

// The paths a hold keeps for one call.
type restoreHold struct {
	toolUseId string
	runId     sidecar.Id
	// by path as the hook named it
	files map[string]*restoreHeldFile
	stop  func() bool
}

// One held path.
type restoreHeldFile struct {
	state *RestoreFileState
	// the sealed copy's name, empty for an absent path or one over the cap
	copyName string
	oversize bool
}

// What a PreToolUse's paths are held by: the registry's points, for Claude Code and Codex. Cursor needs no hold.
func (self *RestorePoints) HookHolds() HookHolds {
	return func(ctx context.Context, network McpNetwork, networkId sidecar.Id, runId sidecar.Id, event *HookEvent) error {
		if event.ToolUseId == "" || len(event.Paths) == 0 || event.Cwd == "" || runId == (sidecar.Id{}) {
			return nil
		}
		if event.Harness != claudeHookHarness && event.Harness != codexHookHarness {
			return nil
		}
		point, err := self.Open(ctx, network, networkId, runId, event.Cwd)
		if err != nil {
			return err
		}
		return point.hold(event)
	}
}

// Seals each named path's bytes under the call's id, timed out after RestoreHoldTimeout.
func (self *RestorePoint) hold(event *HookEvent) error {
	hold := &restoreHold{toolUseId: event.ToolUseId, runId: self.runId, files: map[string]*restoreHeldFile{}}
	settings := self.points.settings
	for _, path := range event.Paths {
		state, content, err := self.stateOf(path, true, settings.RestoreHoldByteCount)
		if err != nil {
			return err
		}
		held := &restoreHeldFile{state: state}
		if state.Kind == RestoreKindFile {
			if content == nil {
				held.oversize = true
			} else {
				copied, name, err := self.copyBytes(restoreHoldCopyPrefix+restoreHoldName(event.ToolUseId)+"/", content)
				if err != nil {
					return err
				}
				if !copied {
					held.oversize = true
				} else {
					held.copyName = name
				}
			}
		}
		hold.files[self.relativePath(path)] = held
	}
	hold.stop = self.points.clock.AfterFunc(settings.RestoreHoldTimeout, func() {
		self.dropHold(event.ToolUseId)
	})
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if old, ok := self.holds[event.ToolUseId]; ok && old.stop != nil {
		old.stop()
	}
	self.holds[event.ToolUseId] = hold
	return nil
}

// A hold's directory name: hex of the id's hash, since a tool_use_id is the harness's own text.
func restoreHoldName(toolUseId string) string {
	sum := sha256.Sum256([]byte(toolUseId))
	return hex.EncodeToString(sum[:8])
}

// Takes a hold out, removing its copies and returning the byte count to the point.
func (self *RestorePoint) dropHold(toolUseId string) {
	hold := func() *restoreHold {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		hold, ok := self.holds[toolUseId]
		if !ok {
			return nil
		}
		delete(self.holds, toolUseId)
		return hold
	}()
	if hold == nil {
		return
	}
	if hold.stop != nil {
		hold.stop()
	}
	for _, held := range hold.files {
		if held.copyName == "" {
			continue
		}
		self.store.Remove(held.copyName)
		self.stateLock.Lock()
		self.manifest.ByteCount -= held.state.Size
		if self.manifest.ByteCount < 0 {
			self.manifest.ByteCount = 0
		}
		self.stateLock.Unlock()
	}
}

// Whether the run holds a path for a call, for tests and `ur hook`'s wait.
func (self *RestorePoint) Holds(toolUseId string, path string) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	hold, ok := self.holds[toolUseId]
	if !ok {
		return false
	}
	_, ok = hold.files[self.relativePath(path)]
	return ok
}

// What recordEdits found.
type restoreRecordedEdits struct {
	paths    []string
	allKnown bool
}

// Records a file-edit PostToolUse's paths in the ledger (§16.7's edit row), each before known only as the header
// says. The hold is dropped once read.
func (self *RestorePoint) recordEdits(ctx context.Context, seq uint64, now time.Time, event *HookEvent, payload []byte) (*restoreRecordedEdits, error) {
	recorded := &restoreRecordedEdits{allKnown: true}
	eventSha256 := restoreEventSha256(event)
	hold := func() *restoreHold {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.holds[event.ToolUseId]
	}()
	if hold != nil {
		defer self.dropHold(event.ToolUseId)
	}
	toolInput := json.RawMessage(hookObjectRaw(payload, "tool_input"))
	for _, path := range event.Paths {
		relative := self.relativePath(path)
		recorded.paths = append(recorded.paths, relative)
		after, afterBytes, err := self.stateOf(path, true, self.points.settings.FileByteCount)
		if err != nil {
			return nil, err
		}
		known := false
		var before *RestoreFileState
		switch event.Harness {
		case cursorHookHarness:
			if afterBytes != nil && after.Kind == RestoreKindFile {
				if beforeBytes, ok := restoreCursorReverse(afterBytes, hookObjectRaw(payload, "edits")); ok {
					sum := sha256.Sum256(beforeBytes)
					before = &RestoreFileState{Kind: RestoreKindFile, Sha256: sum[:], Mode: after.Mode, Size: int64(len(beforeBytes))}
					known = true
				}
			}
		default:
			if hold != nil {
				if held, ok := hold.files[relative]; ok && !held.oversize {
					before, known = self.checkHeld(held, relative, event.ToolName, toolInput, after, afterBytes)
				}
			}
		}
		if !known {
			recorded.allKnown = false
		}
		self.recordEdit(seq, now.UnixMilli(), eventSha256, relative, known, before, after)
	}
	return recorded, self.saveLedger()
}

// The held before, if the call's input re-applied to the held bytes gives the after bytes.
func (self *RestorePoint) checkHeld(held *restoreHeldFile, path string, toolName string, toolInput json.RawMessage, after *RestoreFileState, afterBytes []byte) (*RestoreFileState, bool) {
	var heldBytes []byte
	if held.state.Kind == RestoreKindFile {
		content, err := self.readCopy(held.copyName)
		if err != nil {
			return nil, false
		}
		heldBytes = content
	} else if held.state.Kind != RestoreKindAbsent {
		return nil, false
	}
	expected, expectedAbsent, ok := restoreReapply(toolName, toolInput, path, heldBytes, held.state.Kind == RestoreKindAbsent)
	if !ok {
		return nil, false
	}
	if expectedAbsent {
		if after.Kind != RestoreKindAbsent {
			return nil, false
		}
		return held.state, true
	}
	if after.Kind != RestoreKindFile || afterBytes == nil {
		return nil, false
	}
	if toolName == "NotebookEdit" {
		if !restoreNotebookEquals(expected, afterBytes) {
			return nil, false
		}
		return held.state, true
	}
	if !bytes.Equal(expected, afterBytes) {
		return nil, false
	}
	return held.state, true
}

// The input of the edit tools, as Claude Code's and Codex's documents give it.
type restoreEditInput struct {
	FilePath   string `json:"file_path"`
	OldString  string `json:"old_string"`
	NewString  string `json:"new_string"`
	ReplaceAll bool   `json:"replace_all"`
	Content    string `json:"content"`
	Edits      []struct {
		OldString  string `json:"old_string"`
		NewString  string `json:"new_string"`
		ReplaceAll bool   `json:"replace_all"`
	} `json:"edits"`
	// NotebookEdit
	NotebookPath string `json:"notebook_path"`
	CellId       string `json:"cell_id"`
	CellNumber   *int   `json:"cell_number"`
	NewSource    string `json:"new_source"`
	CellType     string `json:"cell_type"`
	EditMode     string `json:"edit_mode"`
}

// The call's input re-applied to held: the expected after bytes, or that the path is expected absent; ok false
// where the tool, its input or the bytes do not let the result be computed exactly.
func restoreReapply(toolName string, toolInput json.RawMessage, path string, held []byte, heldAbsent bool) (expected []byte, expectedAbsent bool, ok bool) {
	input := &restoreEditInput{}
	if err := json.Unmarshal(toolInput, input); err != nil {
		return nil, false, false
	}
	switch toolName {
	case "Edit":
		if heldAbsent {
			return nil, false, false
		}
		return restoreReplace(held, input.OldString, input.NewString, input.ReplaceAll)
	case "MultiEdit":
		if heldAbsent || len(input.Edits) == 0 {
			return nil, false, false
		}
		current := held
		for _, edit := range input.Edits {
			next, _, ok := restoreReplace(current, edit.OldString, edit.NewString, edit.ReplaceAll)
			if !ok {
				return nil, false, false
			}
			current = next
		}
		return current, false, true
	case "Write":
		return []byte(input.Content), false, true
	case "apply_patch":
		patch := hookStringOrWords(json.RawMessage(hookObjectRaw(toolInput, "command")))
		if patch == "" {
			patch = hookObjectString(toolInput, "input")
		}
		return restoreApplyPatch(patch, path, held, heldAbsent)
	case "NotebookEdit":
		if heldAbsent {
			return nil, false, false
		}
		return restoreNotebookEdit(held, input)
	}
	return nil, false, false
}

// Edit's rule: old_string replaced by new_string, once where it occurs exactly once, or everywhere with replace_all.
// An old_string that is empty or absent, or occurs more than once without replace_all, does not reproduce.
func restoreReplace(held []byte, oldString string, newString string, replaceAll bool) ([]byte, bool, bool) {
	if oldString == "" {
		return nil, false, false
	}
	count := bytes.Count(held, []byte(oldString))
	if count == 0 || (count != 1 && !replaceAll) {
		return nil, false, false
	}
	if replaceAll {
		return bytes.ReplaceAll(held, []byte(oldString), []byte(newString)), false, true
	}
	return bytes.Replace(held, []byte(oldString), []byte(newString), 1), false, true
}

// Cursor's afterFileEdit edits reversed on the after bytes, last first: each new_string must be found exactly once.
// An empty new_string cannot be placed, so it reads ambiguous.
func restoreCursorReverse(after []byte, editsRaw []byte) ([]byte, bool) {
	edits := []struct {
		OldString string `json:"old_string"`
		NewString string `json:"new_string"`
	}{}
	if err := json.Unmarshal(editsRaw, &edits); err != nil || len(edits) == 0 {
		return nil, false
	}
	current := bytes.Clone(after)
	for i := len(edits) - 1; 0 <= i; i -= 1 {
		edit := edits[i]
		if edit.NewString == "" || bytes.Count(current, []byte(edit.NewString)) != 1 {
			return nil, false
		}
		current = bytes.Replace(current, []byte(edit.NewString), []byte(edit.OldString), 1)
	}
	return current, true
}

// One file's section of an apply_patch patch.
type restorePatchSection struct {
	kind   string
	path   string
	moveTo string
	lines  []string
}

// The sections of apply_patch's format: *** Add File:, *** Delete File:, *** Update File: with an optional
// *** Move to:, each followed by its lines until the next header or *** End Patch.
func restorePatchSections(patch string) []*restorePatchSection {
	sections := []*restorePatchSection{}
	var current *restorePatchSection
	for _, line := range strings.Split(strings.ReplaceAll(patch, "\r\n", "\n"), "\n") {
		switch {
		case strings.HasPrefix(line, "*** Begin Patch"), strings.HasPrefix(line, "*** End Patch"):
			continue
		case strings.HasPrefix(line, "*** Add File: "):
			current = &restorePatchSection{kind: "add", path: strings.TrimPrefix(line, "*** Add File: ")}
			sections = append(sections, current)
		case strings.HasPrefix(line, "*** Delete File: "):
			current = &restorePatchSection{kind: "delete", path: strings.TrimPrefix(line, "*** Delete File: ")}
			sections = append(sections, current)
		case strings.HasPrefix(line, "*** Update File: "):
			current = &restorePatchSection{kind: "update", path: strings.TrimPrefix(line, "*** Update File: ")}
			sections = append(sections, current)
		case strings.HasPrefix(line, "*** Move to: ") && current != nil:
			current.moveTo = strings.TrimPrefix(line, "*** Move to: ")
		case current != nil:
			current.lines = append(current.lines, line)
		}
	}
	for _, section := range sections {
		// the patch's own trailing newline is no line of the file
		for 0 < len(section.lines) && section.lines[len(section.lines)-1] == "" {
			section.lines = section.lines[:len(section.lines)-1]
		}
	}
	return sections
}

// apply_patch's patch applied to the held bytes of path: an added file's lines, a deleted file's absence, or an
// updated file's hunks, each hunk's old lines found in order from the previous hunk's end. A moved file's old path
// becomes absent and its new path takes the result.
func restoreApplyPatch(patch string, path string, held []byte, heldAbsent bool) ([]byte, bool, bool) {
	sections := restorePatchSections(patch)
	for _, section := range sections {
		switch section.kind {
		case "add":
			if section.path != path {
				continue
			}
			if !heldAbsent {
				return nil, false, false
			}
			lines := []string{}
			for _, line := range section.lines {
				if strings.HasPrefix(line, "+") {
					lines = append(lines, line[1:])
				} else if strings.TrimSpace(line) != "" {
					return nil, false, false
				}
			}
			return []byte(strings.Join(lines, "\n") + "\n"), false, true
		case "delete":
			if section.path == path {
				return nil, true, true
			}
		case "update":
			if section.moveTo != "" && section.moveTo == path {
				// the new name's before is absent, and nothing here reproduces its bytes from the old path's hold
				return nil, false, false
			}
			if section.path != path {
				continue
			}
			if heldAbsent {
				return nil, false, false
			}
			if section.moveTo != "" {
				return nil, true, true
			}
			return restoreApplyHunks(held, section.lines)
		}
	}
	return nil, false, false
}

// The hunks of an Update File section applied to held: lines starting "@@" open a hunk, " " is context, "-" is
// removed and "+" added; each hunk's old lines are found once, in order, after the previous hunk.
func restoreApplyHunks(held []byte, lines []string) ([]byte, bool, bool) {
	text := string(held)
	trailingNewline := strings.HasSuffix(text, "\n")
	fileLines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if text == "" {
		fileLines = []string{}
	}
	type hunk struct {
		old []string
		new []string
	}
	hunks := []*hunk{}
	var current *hunk
	for _, line := range lines {
		switch {
		case strings.HasPrefix(line, "@@"):
			current = &hunk{}
			hunks = append(hunks, current)
		case line == "*** End of File":
			continue
		case current == nil:
			if strings.TrimSpace(line) == "" {
				continue
			}
			current = &hunk{}
			hunks = append(hunks, current)
			fallthrough
		default:
			if line == "" {
				// a blank context line with its marker dropped
				current.old = append(current.old, "")
				current.new = append(current.new, "")
				continue
			}
			switch line[0] {
			case ' ':
				current.old = append(current.old, line[1:])
				current.new = append(current.new, line[1:])
			case '-':
				current.old = append(current.old, line[1:])
			case '+':
				current.new = append(current.new, line[1:])
			default:
				return nil, false, false
			}
		}
	}
	result := []string{}
	cursor := 0
	for _, hunk := range hunks {
		at := -1
		for i := cursor; i+len(hunk.old) <= len(fileLines); i += 1 {
			if restoreLinesEqual(fileLines[i:i+len(hunk.old)], hunk.old) {
				at = i
				break
			}
		}
		if at < 0 {
			return nil, false, false
		}
		result = append(result, fileLines[cursor:at]...)
		result = append(result, hunk.new...)
		cursor = at + len(hunk.old)
	}
	result = append(result, fileLines[cursor:]...)
	joined := strings.Join(result, "\n")
	if trailingNewline || len(hunks) != 0 {
		joined += "\n"
	}
	return []byte(joined), false, true
}

func restoreLinesEqual(a []string, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// A notebook's cells, as the check reads them: id, type and source joined.
type restoreNotebookCell struct {
	Id       string          `json:"id"`
	CellType string          `json:"cell_type"`
	Source   json.RawMessage `json:"source"`
}

// A cell's source as one string, from a string or a list of strings.
func restoreCellSource(raw json.RawMessage) (string, bool) {
	text := ""
	if json.Unmarshal(raw, &text) == nil {
		return text, true
	}
	parts := []string{}
	if json.Unmarshal(raw, &parts) == nil {
		return strings.Join(parts, ""), true
	}
	return "", false
}

// NotebookEdit's cell applied to the held notebook: the expected notebook is the held one with the named cell
// replaced, inserted after or deleted. Since the harness rewrites the file in its own formatting, the expected bytes
// cannot be reproduced; the caller compares parsed cells instead (restoreNotebookEquals). This answers the expected
// cells as JSON of the check's own form, and checkHeld's byte comparison is replaced for notebooks below.
func restoreNotebookEdit(held []byte, input *restoreEditInput) ([]byte, bool, bool) {
	cells, ok := restoreNotebookCells(held)
	if !ok {
		return nil, false, false
	}
	index := -1
	if input.CellId != "" {
		for i, cell := range cells {
			if cell.Id == input.CellId {
				index = i
			}
		}
	} else if input.CellNumber != nil {
		index = *input.CellNumber
	}
	mode := input.EditMode
	if mode == "" {
		mode = "replace"
	}
	newCell := &restoreNotebookCell{Id: input.CellId, CellType: input.CellType}
	if encoded, err := json.Marshal(input.NewSource); err == nil {
		newCell.Source = encoded
	}
	switch mode {
	case "replace":
		if index < 0 || len(cells) <= index {
			return nil, false, false
		}
		if newCell.CellType == "" {
			newCell.CellType = cells[index].CellType
		}
		newCell.Id = cells[index].Id
		cells[index] = newCell
	case "insert":
		if newCell.CellType == "" {
			return nil, false, false
		}
		if index < 0 || len(cells) < index {
			index = len(cells)
		}
		cells = append(cells[:index], append([]*restoreNotebookCell{newCell}, cells[index:]...)...)
	case "delete":
		if index < 0 || len(cells) <= index {
			return nil, false, false
		}
		cells = append(cells[:index], cells[index+1:]...)
	default:
		return nil, false, false
	}
	return restoreNotebookCanonical(cells), false, true
}

// A notebook's cells, false where the bytes are no notebook.
func restoreNotebookCells(content []byte) ([]*restoreNotebookCell, bool) {
	notebook := struct {
		Cells []*restoreNotebookCell `json:"cells"`
	}{}
	if err := json.Unmarshal(content, &notebook); err != nil || notebook.Cells == nil {
		return nil, false
	}
	return notebook.Cells, true
}

// Cells in the check's own canonical form: each as type, id and joined source, so two notebooks compare by cells
// alone, their formatting and metadata aside.
func restoreNotebookCanonical(cells []*restoreNotebookCell) []byte {
	canonical := [][]string{}
	for _, cell := range cells {
		source, _ := restoreCellSource(cell.Source)
		canonical = append(canonical, []string{cell.CellType, cell.Id, source})
	}
	encoded, _ := json.Marshal(canonical)
	return encoded
}

// Whether afterBytes, a notebook, holds exactly the expected cells (restoreNotebookEdit's answer), inserted cells
// matched by type and source alone, since the harness mints their ids.
func restoreNotebookEquals(expected []byte, afterBytes []byte) bool {
	afterCells, ok := restoreNotebookCells(afterBytes)
	if !ok {
		return false
	}
	expectedRows := [][]string{}
	if err := json.Unmarshal(expected, &expectedRows); err != nil {
		return false
	}
	if len(expectedRows) != len(afterCells) {
		return false
	}
	for i, row := range expectedRows {
		source, _ := restoreCellSource(afterCells[i].Source)
		if row[0] != afterCells[i].CellType || row[2] != source {
			return false
		}
		if row[1] != "" && row[1] != afterCells[i].Id {
			return false
		}
	}
	return true
}
