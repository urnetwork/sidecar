//go:build !js && !ios && !android && !sdk_mobile_bind

// §16.7's context, title, change and blob rows (RECORD.md sections 4.3 and 6.4):
//
//	context   stage 1 at a run's SessionStart, with the harness, its version where the payload names one (Cursor's
//	          cursor_version), model, permission_mode, the newest session ids, the project and branch (`.ur`'s
//	          project, else the worktree's top-level name; git's branch), the title where known, and the
//	          instruction files the harness loads by scope, name, hash and size, never their text; stage 2 at a
//	          later event where the model or mode changed, and at Claude Code's InstructionsLoaded, with the file it
//	          names among them
//	title     Claude Code's session_title at SessionStart or UserPromptSubmit when set, else the first user
//	          prompt's first line, 120 B after redaction, for the run card and the context entry
//	change    each hook's scan of MCP-M3-20's restore point: the commits since the last scan, the counts by
//	          attribution and each changed path with its hashes, mode and attribution
//	blob      the after bytes of each changed file within Ingest.FileByteCount, redacted, with the hash of the bytes
//	          as captured; a hash already stored is not stored again; a file past the cap goes by its hash in the
//	          change row alone, an oversize gap; one evs push per tree and multi-part pushes are the writer's
//	          (EVS1-M2-26)
//
// Instruction files are read for their hash alone, and their names are their base names.

package mcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// ContextBody's caps that this file applies before the writer checks them: format values of RECORD.md section 6.4.
const (
	ingestTitleByteCount          = 120
	ingestSessionIdCount          = 4
	ingestInstructionFileMax      = 64
	ingestInstructionScopeManaged = 1
	ingestInstructionScopeUser    = 2
	ingestInstructionScopeProject = 3
	ingestChangeCaptureHooks      = 1
	ingestChangeCaptureScan       = 2
	// Claude Code's event for an instruction file it loaded, and Cursor's payload field for its own version
	ingestInstructionsLoadedEvent = "InstructionsLoaded"
	ingestCursorVersionField      = "cursor_version"
)

// The context rows: stage 1 at SessionStart, stage 2 when the model or mode changes, and the title when it arrives.
func (self *Ingest) captureContextWithLock(ctx context.Context, run *ingestRun, redactor *sidecar.Redactor, event *HookEvent, payload []byte) {
	state := run.state
	if title := ingestPayloadString(payload, "session_title"); title != "" {
		self.setTitleWithLock(ctx, run, redactor, title)
	}
	switch {
	case event.Kind == HookEventSessionStart || !state.Started:
		// a harness that reports no start opens its run at its first event
		stage := uint32(1)
		if state.Started {
			if event.Kind != HookEventSessionStart {
				return
			}
			// a SessionStart on a run already started: a resume, restated
			stage = 2
		}
		if !state.Started {
			state.StartedMillis = self.clock.Now().UnixMilli()
			state.Started = true
			state.Project, state.Branch = self.projectAndBranch(ctx, event.Cwd)
			state.AgentLabel = self.agentLabel(event.Cwd)
		}
		state.Model = event.Model
		state.PermissionMode = event.PermissionMode
		run.dirty = true
		self.appendContextWithLock(ctx, run, redactor, stage, event, payload)
		if stage == 1 {
			self.lifecycleStartWithLock(ctx, run)
		}
	default:
		changed := false
		if event.Model != "" && event.Model != state.Model {
			state.Model = event.Model
			changed = true
		}
		if event.PermissionMode != "" && event.PermissionMode != state.PermissionMode {
			state.PermissionMode = event.PermissionMode
			changed = true
		}
		if event.HarnessEvent == ingestInstructionsLoadedEvent {
			// the instructions in force changed: restated with the loaded file by hash
			changed = true
		}
		if changed {
			run.dirty = true
			self.appendContextWithLock(ctx, run, redactor, 2, event, payload)
		}
	}
}

// The run's who, what and where to the lifecycle: all RunStarted carries, and all of a session that leaves the
// ingest for the directory (I-20).
func (self *Ingest) lifecycleStartWithLock(ctx context.Context, run *ingestRun) {
	if self.lifecycle == nil {
		return
	}
	state := run.state
	self.lifecycle.RunStarted(ctx, run.networkId, &RunLifecycleStart{
		RunId:      run.runId,
		Harness:    state.Harness,
		AgentLabel: state.AgentLabel,
		Model:      state.Model,
		Title:      state.Title,
		Project:    state.Project,
		Branch:     state.Branch,
	})
}

// One context entry of stage.
func (self *Ingest) appendContextWithLock(ctx context.Context, run *ingestRun, redactor *sidecar.Redactor, stage uint32, event *HookEvent, payload []byte) {
	state := run.state
	if event.Harness == cursorHookHarness {
		if version := ingestPayloadString(payload, ingestCursorVersionField); version != "" && version != state.HarnessVersion {
			state.HarnessVersion = version
			run.dirty = true
		}
	}
	harnessVersion, _ := ingestCut([]byte(state.HarnessVersion), 64)
	sessionIds := []string{}
	if runs, err := run.network.Runs(); err == nil {
		if file, err := runs.Get(run.runId); err == nil {
			sessionIds = slices.Clone(file.SessionIds)
		}
	}
	if len(sessionIds) == 0 && state.SessionId != "" {
		sessionIds = []string{state.SessionId}
	}
	if ingestSessionIdCount < len(sessionIds) {
		sessionIds = sessionIds[len(sessionIds)-ingestSessionIdCount:]
	}
	for i, sessionId := range sessionIds {
		cut, _ := ingestCut([]byte(sessionId), 64)
		sessionIds[i] = string(cut)
	}
	model, _ := ingestCut([]byte(state.Model), 64)
	mode, _ := ingestCut([]byte(state.PermissionMode), 32)
	project, _ := ingestCut([]byte(state.Project), 128)
	branch, _ := ingestCut([]byte(state.Branch), 128)
	loaded := (*protocol.InstructionFile)(nil)
	if event.HarnessEvent == ingestInstructionsLoadedEvent {
		loaded = ingestLoadedInstructionFile(payload)
	}
	files, truncations := self.instructionFiles(event.Cwd, loaded)
	self.appendWithLock(ctx, run, &ingestEntry{
		kind:   sidecar.RecordKindContext,
		source: sidecar.RecordSourceHook,
		body: &protocol.ContextBody{
			Stage:            stage,
			Harness:          state.Harness,
			HarnessVersion:   string(harnessVersion),
			AgentLabel:       state.AgentLabel,
			SessionIds:       sessionIds,
			Model:            string(model),
			PermissionMode:   string(mode),
			Project:          string(project),
			Branch:           string(branch),
			Title:            state.Title,
			InstructionFiles: files,
			Truncations:      truncations,
		},
		coverageSource: sidecar.RecordCoverageSourceHooks,
	})
}

// Sets the run's title once: 120 B after redaction, its first line.
func (self *Ingest) setTitleWithLock(ctx context.Context, run *ingestRun, redactor *sidecar.Redactor, title string) {
	if run.state.Title != "" {
		return
	}
	line, _, _ := strings.Cut(strings.TrimSpace(title), "\n")
	redacted := self.redact(ctx, run, redactor, []byte(line))
	cut, _ := ingestCut(redacted, ingestTitleByteCount)
	if len(cut) == 0 {
		return
	}
	run.state.Title = string(cut)
	run.dirty = true
	if run.state.Started {
		// the title arrived after the run's start: restated to the lifecycle
		self.lifecycleStartWithLock(ctx, run)
	}
}

// A UserPromptSubmit: the title from the first prompt when none is set, and the run card's prompts.
func (self *Ingest) capturePromptWithLock(ctx context.Context, run *ingestRun, redactor *sidecar.Redactor, payload []byte) {
	prompt := ingestPayloadString(payload, "prompt")
	if prompt == "" {
		return
	}
	self.setTitleWithLock(ctx, run, redactor, prompt)
	state := run.state
	room := self.settings.RunCardPromptByteCount - len(state.Prompts)
	if room <= 0 {
		return
	}
	redacted := self.redact(ctx, run, redactor, []byte(prompt))
	cut, _ := ingestCut(redacted, int64(room))
	if len(state.Prompts) != 0 {
		state.Prompts += "\n"
	}
	state.Prompts += string(cut)
	run.dirty = true
}

// §16.11's project key and git's branch for a worktree: `.ur`'s project where one is set, else the top level's base
// name; the branch from `git rev-parse --abbrev-ref HEAD`, empty off a branch or outside a repository.
func (self *Ingest) projectAndBranch(ctx context.Context, cwd string) (string, string) {
	if cwd == "" {
		return "", ""
	}
	project := ""
	if found, err := sidecar.FindSidecarProject(cwd, self.home); err == nil && found != nil && found.Project != "" {
		project = found.Project
	}
	branch := ""
	if self.restore != nil {
		if top, err := self.restore.runGit(ctx, cwd, "rev-parse", "--show-toplevel"); err == nil {
			if project == "" {
				project = filepath.Base(strings.TrimSpace(string(top)))
			}
			if ref, err := self.restore.runGit(ctx, cwd, "rev-parse", "--abbrev-ref", "HEAD"); err == nil {
				branch = strings.TrimSpace(string(ref))
				if branch == "HEAD" {
					branch = ""
				}
			}
		}
	}
	if project == "" {
		project = filepath.Base(cwd)
	}
	return project, branch
}

// The agent label `.ur` sets for the project, else none.
func (self *Ingest) agentLabel(cwd string) string {
	if cwd == "" {
		return ""
	}
	found, err := sidecar.FindSidecarProject(cwd, self.home)
	if err != nil || found == nil {
		return ""
	}
	if _, err := sidecar.ParseSidecarAgent(found.Agent); err != nil {
		return ""
	}
	return found.Agent
}

// The file an InstructionsLoaded names, by hash and size: its file_path read for the hash alone, its scope from
// memory_type (Managed, User, else the project's). Nil where the payload names no readable regular file.
func ingestLoadedInstructionFile(payload []byte) *protocol.InstructionFile {
	path := ingestPayloadString(payload, "file_path")
	if path == "" || !filepath.IsAbs(path) {
		return nil
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil
	}
	scope := uint32(ingestInstructionScopeProject)
	switch ingestPayloadString(payload, "memory_type") {
	case "Managed":
		scope = ingestInstructionScopeManaged
	case "User":
		scope = ingestInstructionScopeUser
	}
	return ingestHashFile(scope, path)
}

// The instruction files under cwd and the home, by scope, base name, hash and size, at most 64, with a truncation
// warning for each past it. A directory among the names lists its files. loaded, the file an InstructionsLoaded
// named, goes first when the lists do not already hold it.
func (self *Ingest) instructionFiles(cwd string, loaded *protocol.InstructionFile) ([]*protocol.InstructionFile, []string) {
	files := []*protocol.InstructionFile{}
	truncations := []string{}
	add := func(scope uint32, absolute string) {
		info, err := os.Lstat(absolute)
		if err != nil {
			return
		}
		if info.IsDir() {
			entries, err := os.ReadDir(absolute)
			if err != nil {
				return
			}
			for _, entry := range entries {
				if entry.Type().IsRegular() {
					if hashed := ingestHashFile(scope, filepath.Join(absolute, entry.Name())); hashed != nil {
						files = append(files, hashed)
					}
				}
			}
			return
		}
		if !info.Mode().IsRegular() {
			return
		}
		if hashed := ingestHashFile(scope, absolute); hashed != nil {
			files = append(files, hashed)
		}
	}
	if cwd != "" {
		for _, name := range self.settings.InstructionProjectFileNames {
			add(ingestInstructionScopeProject, filepath.Join(cwd, filepath.FromSlash(name)))
		}
	}
	if self.home != "" {
		for _, name := range self.settings.InstructionUserFileNames {
			add(ingestInstructionScopeUser, filepath.Join(self.home, filepath.FromSlash(name)))
		}
	}
	if loaded != nil && !slices.ContainsFunc(files, func(file *protocol.InstructionFile) bool {
		return file.Name == loaded.Name && bytes.Equal(file.Sha256, loaded.Sha256)
	}) {
		files = append([]*protocol.InstructionFile{loaded}, files...)
	}
	if ingestInstructionFileMax < len(files) {
		for _, file := range files[ingestInstructionFileMax:] {
			if len(truncations) < 16 {
				name, _ := ingestCut([]byte(file.Name), 100)
				truncations = append(truncations, string(name)+": not listed")
			}
		}
		files = files[:ingestInstructionFileMax]
	}
	return files, truncations
}

// One instruction file by hash and size, its text never kept.
func ingestHashFile(scope uint32, absolute string) *protocol.InstructionFile {
	file, err := os.Open(absolute)
	if err != nil {
		return nil
	}
	defer file.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil {
		return nil
	}
	name, _ := ingestCut([]byte(filepath.Base(absolute)), 128)
	return &protocol.InstructionFile{Scope: scope, Name: string(name), Sha256: hash.Sum(nil), Size: uint64(size)}
}

// A hook's scan of the restore point: a change entry with each path's hashes and attribution, and a blob for each
// changed file's after bytes within the cap.
func (self *Ingest) captureScanWithLock(ctx context.Context, run *ingestRun, redactor *sidecar.Redactor, event *HookEvent, payload []byte) {
	if self.restore == nil {
		return
	}
	scan, err := self.restore.NoteEvent(ctx, run.network, run.networkId, run.runId, event, payload)
	if err != nil {
		self.log.Warningf("[ingest]a scan did not run: %s", err)
		self.gap(ctx, run.network, run.networkId, run.runId, sidecar.RecordCoverageGapMissedEvent)
		return
	}
	if scan == nil {
		return
	}
	self.captureScanResultWithLock(ctx, run, redactor, scan)
}

// A scan's change entry and blobs: nothing for a scan that found no change and no commit.
func (self *Ingest) captureScanResultWithLock(ctx context.Context, run *ingestRun, redactor *sidecar.Redactor, scan *RestoreScan) {
	if !slices.Contains(run.state.Sources, sidecar.RecordCoverageSourceScan) {
		run.state.Sources = append(run.state.Sources, sidecar.RecordCoverageSourceScan)
		run.dirty = true
	}
	if len(scan.Changes) == 0 && len(scan.Commits) == 0 {
		return
	}
	if scan.Truncated {
		self.gap(ctx, run.network, run.networkId, run.runId, sidecar.RecordCoverageGapTruncation)
	}
	body := &protocol.ChangeBody{
		Project:    run.state.Project,
		BaseCommit: scan.HeadCommit,
		Commits:    scan.Commits,
		PathCount:  uint32(scan.PathCount),
		Capture:    ingestChangeCaptureHooks | ingestChangeCaptureScan,
	}
	for _, change := range scan.Changes {
		self.touchWithLock(run, change.Path)
		row := &protocol.ChangedPath{
			Path:        change.Path,
			AfterSha256: change.After.Sha256,
			Mode:        change.After.Mode,
			Attribution: uint32(change.Attribution),
		}
		if change.BeforeKnown && change.Before != nil {
			row.BeforeSha256 = change.Before.Sha256
		}
		switch change.Attribution {
		case RestoreAttributionEdit:
			body.EditCount += 1
		case RestoreAttributionShell:
			body.ShellCount += 1
		default:
			body.ForeignCount += 1
		}
		if change.After.Kind == RestoreKindFile {
			if change.AfterBytes == nil {
				// past FileByteCount: by hash alone, its bytes cut
				self.gap(ctx, run.network, run.networkId, run.runId, sidecar.RecordCoverageGapOversize)
			} else if entryId := self.captureBlobWithLock(ctx, run, redactor, change); entryId != nil {
				row.BlobEntryId = entryId
			}
		}
		body.Paths = append(body.Paths, row)
	}
	self.appendWithLock(ctx, run, &ingestEntry{
		kind:           sidecar.RecordKindChange,
		source:         sidecar.RecordSourceObserved,
		body:           body,
		coverageSource: sidecar.RecordCoverageSourceScan,
	})
}

// A changed file's after bytes as a blob, once per hash: its entry id for the change row, nil where none was written.
func (self *Ingest) captureBlobWithLock(ctx context.Context, run *ingestRun, redactor *sidecar.Redactor, change *RestoreChange) []byte {
	state := run.state
	hashHex := hex.EncodeToString(change.After.Sha256)
	if slices.Contains(state.BlobHashes, hashHex) {
		return nil
	}
	redacted, matches := redactor.Redact(change.AfterBytes)
	for range matches {
		self.gap(ctx, run.network, run.networkId, run.runId, sidecar.RecordCoverageGapRedaction)
	}
	entryId := []byte(nil)
	writer, err := self.writers(run.network)
	if err != nil {
		self.gap(ctx, run.network, run.networkId, run.runId, sidecar.RecordCoverageGapMissedEvent)
		return nil
	}
	if !self.budgetWithLock(ctx, run, int64(len(redacted))) {
		return nil
	}
	runId := run.runId
	refs, err := writer.Append(&sidecar.RecordDraft{
		Kind:       sidecar.RecordKindBlob,
		Source:     sidecar.RecordSourceObserved,
		RunId:      &runId,
		TimeMillis: self.clock.Now().UnixMilli(),
		Body: &protocol.BlobBody{
			Path:     change.Path,
			Content:  redacted,
			Sha256:   change.After.Sha256,
			Redacted: len(matches) != 0,
			Size:     uint64(change.After.Size),
		},
	})
	if err != nil {
		self.log.Warningf("[ingest]a blob was not appended: %s", err)
		self.gap(ctx, run.network, run.networkId, run.runId, sidecar.RecordCoverageGapMissedEvent)
		return nil
	}
	for _, ref := range refs {
		if ref.Spooled {
			continue
		}
		if state.FirstSeq == 0 || ref.Seq < state.FirstSeq {
			state.FirstSeq = ref.Seq
		}
		if state.LastSeq < ref.Seq {
			state.LastSeq = ref.Seq
		}
		entryId = ref.EntryId[:]
	}
	state.BlobHashes = append(state.BlobHashes, hashHex)
	if count := max(self.settings.IngestBlobHashCount, 1); count < len(state.BlobHashes) {
		state.BlobHashes = state.BlobHashes[len(state.BlobHashes)-count:]
	}
	run.dirty = true
	return entryId
}

// Charges byteCount to the run's hour: false, and an oversize gap, past RunHourByteCount.
func (self *Ingest) budgetWithLock(ctx context.Context, run *ingestRun, byteCount int64) bool {
	state := run.state
	now := self.clock.Now().UnixMilli()
	if state.HourStartMillis == 0 || now-state.HourStartMillis >= 60*60*1000 {
		state.HourStartMillis = now
		state.HourByteCount = 0
		run.dirty = true
	}
	if self.settings.RunHourByteCount < state.HourByteCount+byteCount {
		self.gap(ctx, run.network, run.networkId, run.runId, sidecar.RecordCoverageGapOversize)
		return false
	}
	state.HourByteCount += byteCount
	run.dirty = true
	return true
}
