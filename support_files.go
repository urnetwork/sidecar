//go:build !ios_extension && !sidecar_http

// The files a support message names (DESIGN-COMPUTE §28.7, Q-SUP-5), read for the support client's form check and
// scan (support_form.go): at most 3, each at most 10 MiB and a regular file.
//
//	an agent's    read as the Harness's file tools read them, beneath one root: the session's worktree for MCP's
//	              support_send, the run's for ur support send from a harness's process. os.Root refuses a name that
//	              leaves the root, by .. or by a link, and an absolute name is taken only where it lies beneath it.
//	              A message naming a file always waits for the person, kind 27 with rule attachment (§28.8), whose
//	              card shows each whole
//	the person's  read where they name them, an absolute path each: their own act at a terminal or in an app
//
// SupportCallerRun (support_files_daemon.go, on the legs that read process ancestry) names the run a caller's process
// ancestry binds, whose worktree and taint reasons ur support send from a harness's process carries. Package-level
// functions are safe for concurrent use.

package sidecar

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// A file past its bound, or no regular one.
var errSupportFileUnread = errors.New("support: a file that is no regular one, or past its bound")

// The refusal of the file at index.
func supportFileRefused(index int) *SupportRefusalError {
	refusal := supportRefused(SupportRefusalFileRefused)
	refusal.FileIndex = index
	return refusal
}

// The files names name, read beneath root: file_refused, naming the file's place, for more names than
// settings.FileMaxCount, a root that is no absolute directory, a name that leaves the root or opens no regular file,
// and a file past FileMaxByteCount. Each file takes its base name.
func SupportReadFiles(root string, names []string, settings *SupportSettings) ([]*SupportFile, error) {
	if len(names) == 0 {
		return nil, nil
	}
	if settings.FileMaxCount < len(names) {
		return nil, supportFileRefused(settings.FileMaxCount)
	}
	if root == "" || !filepath.IsAbs(root) {
		return nil, supportFileRefused(0)
	}
	opened, err := os.OpenRoot(root)
	if err != nil {
		return nil, supportFileRefused(0)
	}
	defer opened.Close()
	files := make([]*SupportFile, 0, len(names))
	for i, name := range names {
		relative, ok := supportRootRelative(root, name)
		if !ok {
			return nil, supportFileRefused(i)
		}
		file, err := opened.Open(relative)
		if err != nil {
			return nil, supportFileRefused(i)
		}
		data, err := supportReadRegular(file, settings.FileMaxByteCount)
		file.Close()
		if err != nil {
			return nil, supportFileRefused(i)
		}
		files = append(files, &SupportFile{Name: filepath.Base(relative), Data: data})
	}
	return files, nil
}

// The person's own files, each at the absolute path they named: file_refused for more than settings.FileMaxCount, a
// path that is not absolute or opens no regular file, and a file past FileMaxByteCount.
func SupportReadPersonFiles(paths []string, settings *SupportSettings) ([]*SupportFile, error) {
	if settings.FileMaxCount < len(paths) {
		return nil, supportFileRefused(settings.FileMaxCount)
	}
	files := make([]*SupportFile, 0, len(paths))
	for i, path := range paths {
		if !filepath.IsAbs(path) {
			return nil, supportFileRefused(i)
		}
		file, err := os.Open(path)
		if err != nil {
			return nil, supportFileRefused(i)
		}
		data, err := supportReadRegular(file, settings.FileMaxByteCount)
		file.Close()
		if err != nil {
			return nil, supportFileRefused(i)
		}
		files = append(files, &SupportFile{Name: filepath.Base(path), Data: data})
	}
	return files, nil
}

// name as a path beneath root: a relative one cleaned, an absolute one only where it lies beneath root; false for one
// that names the root itself or climbs out of it.
func supportRootRelative(root string, name string) (string, bool) {
	if name == "" {
		return "", false
	}
	if filepath.IsAbs(name) {
		relative, err := filepath.Rel(root, name)
		if err != nil {
			return "", false
		}
		name = relative
	}
	cleaned := filepath.Clean(name)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) || filepath.IsAbs(cleaned) {
		return "", false
	}
	return cleaned, true
}

// A regular file's bytes, at most maxByteCount, read within the bound whatever its size said.
func supportReadRegular(file *os.File, maxByteCount int64) ([]byte, error) {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || maxByteCount < info.Size() {
		return nil, errSupportFileUnread
	}
	data, err := supportReadAll(file, maxByteCount)
	if err != nil {
		return nil, errSupportFileUnread
	}
	return data, nil
}

// A run file as support's gate reads it for an external harness's message: counted tainted whatever its file says
// (Q-SUP-8), its file's taint reasons, and no mark, which only the Harness's runs carry. Nil reads as a run with no
// file, tainted with no reasons.
func SupportRunOfFile(runId Id, file *RunFile) *SupportRun {
	run := &SupportRun{RunId: runId, Tainted: true, MarksKnown: true}
	if file != nil {
		run.RunId = file.RunId
		for _, reason := range file.TaintReasons {
			run.TaintReasons = append(run.TaintReasons, string(reason))
		}
	}
	return run
}
