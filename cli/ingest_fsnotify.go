// The daemon's file watch for §16.18's filesystem capture (mcp's ingest_fsevents.go; MCP-M6-03): fsnotify on a
// worktree's top level and on every directory under it but .git, a directory that appears added as it does, past
// Ingest.FileEventDirectoryCount refused. fsnotify watches no tree on its own, and an overflow it reports is a lost
// report, which mcp counts as a gap. Each event's path is relative to the worktree's root, with / between segments;
// a chmod changes no bytes and is passed over. Nothing here logs a path (I-13).

package main

import (
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
	"sync"

	"github.com/fsnotify/fsnotify"

	"github.com/urnetwork/sidecar/mcp"
)

// git's own directory, which no worktree change is in.
const urFileWatchGitDirectory = ".git"

// A worktree past Ingest.FileEventDirectoryCount directories.
var errUrFileWatchTooMany = errors.New("the worktree holds more directories than a watch may")

// Watches root and every directory under it but .git, reporting to sink until stop. See the file header.
func urFsnotifyWatch(root string, directoryCount int, sink *mcp.IngestFileWatchSink) (func(), error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	var stateLock sync.Mutex
	count := 0
	add := func(directory string) error {
		return filepath.WalkDir(directory, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				// a directory removed under the walk is no error of the watch's
				return nil
			}
			if !entry.IsDir() {
				return nil
			}
			if entry.Name() == urFileWatchGitDirectory {
				return filepath.SkipDir
			}
			stateLock.Lock()
			full := directoryCount <= count
			count += 1
			stateLock.Unlock()
			if full {
				return errUrFileWatchTooMany
			}
			return watcher.Add(path)
		})
	}
	if err := add(root); err != nil {
		watcher.Close()
		return nil, err
	}
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		for {
			select {
			case <-done:
				return
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				relative, err := filepath.Rel(root, event.Name)
				if err != nil || relative == "." || strings.HasPrefix(relative, "..") {
					continue
				}
				relative = filepath.ToSlash(relative)
				if relative == urFileWatchGitDirectory || strings.HasPrefix(relative, urFileWatchGitDirectory+"/") {
					continue
				}
				var op mcp.IngestFileOp
				switch {
				case event.Has(fsnotify.Create):
					op = mcp.IngestFileCreate
					if err := add(event.Name); errors.Is(err, errUrFileWatchTooMany) {
						sink.Lost()
					}
				case event.Has(fsnotify.Write):
					op = mcp.IngestFileWrite
				case event.Has(fsnotify.Remove):
					op = mcp.IngestFileDelete
				case event.Has(fsnotify.Rename):
					op = mcp.IngestFileRename
				default:
					continue
				}
				sink.Change(&mcp.IngestFileChange{Path: relative, Op: op})
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				if errors.Is(err, fsnotify.ErrEventOverflow) {
					sink.Lost()
				}
			}
		}
	}()
	return func() {
		close(done)
		watcher.Close()
		<-finished
	}, nil
}
