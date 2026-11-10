//go:build !js && !ios_extension

// A SidecarStoreBackend over OS files, for desktops and for an app's StateDir. Temp files all sit in
// <state>/tmp, so a kill leaves them in one place to sweep. js has no files, and the page Worker's
// main brings IndexedDB instead (§18.10).
//
// <state> and everything under it is the user's alone: 0700 directories and 0600 files.

package sidecar

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
)

// Where temp files go, inside <state>.
const osBackendTempDirectoryName = "tmp"

// What osStoreBackend's directories and files are made with.
const (
	osBackendDirectoryMode fs.FileMode = 0o700
	osBackendFileMode      fs.FileMode = 0o600
)

// A backend rooted at directory, which it makes if it has to. directory is §5.9's <state>, or an
// app's StateDir.
func NewSidecarOsBackend(directory string) (SidecarStoreBackend, error) {
	if !filepath.IsAbs(directory) {
		return nil, errors.New("a state directory must be absolute")
	}
	tempDirectory := filepath.Join(directory, osBackendTempDirectoryName)
	if err := makeOsDirectory(tempDirectory); err != nil {
		return nil, err
	}
	return &osStoreBackend{
		directory:     directory,
		tempDirectory: tempDirectory,
	}, nil
}

// Files under one directory. Holds no state of its own, so it is safe for concurrent use.
type osStoreBackend struct {
	directory     string
	tempDirectory string
}

// The OS path of path, refusing one that would leave the directory. The layers above only build
// clean paths, so this answers a bug, not an input.
func (self *osStoreBackend) osPath(storePath string) (string, error) {
	osPath := filepath.FromSlash(storePath)
	if !filepath.IsLocal(osPath) {
		return "", ErrSidecarStoreName
	}
	return filepath.Join(self.directory, osPath), nil
}

// Answers ErrSidecarStoreAbsent only for a file that is not there.
func (self *osStoreBackend) Open(storePath string) (io.ReadCloser, error) {
	osPath, err := self.osPath(storePath)
	if err != nil {
		return nil, err
	}
	file, err := os.Open(osPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrSidecarStoreAbsent
	}
	if err != nil {
		return nil, storeFault(err)
	}
	return &osStoreReader{file: file}, nil
}

// A new 0600 file in <state>/tmp.
func (self *osStoreBackend) CreateTemp() (SidecarStoreBackendFile, error) {
	file, err := os.CreateTemp(self.tempDirectory, "write-")
	if err != nil {
		return nil, storeFault(err)
	}
	return &osStoreFile{backend: self, file: file}, nil
}

// fsyncs the directory holding path.
func (self *osStoreBackend) SyncDirectory(storePath string) error {
	osPath, err := self.osPath(storePath)
	if err != nil {
		return err
	}
	return syncOsDirectory(filepath.Dir(osPath))
}

// Windows opens no directory for fsync, and NTFS journals the rename itself.
func syncOsDirectory(directory string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	file, err := os.Open(directory)
	if err != nil {
		return storeFault(err)
	}
	defer file.Close()
	if err := file.Sync(); err != nil {
		return storeFault(err)
	}
	return nil
}

// Removes the file, leaving its directory.
func (self *osStoreBackend) Remove(storePath string) error {
	osPath, err := self.osPath(storePath)
	if err != nil {
		return err
	}
	if err := os.Remove(osPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return storeFault(err)
	}
	return nil
}

// Walks from the deepest directory the prefix fixes, so a listing of one directory never walks the
// whole state.
func (self *osStoreBackend) List(prefix string) ([]SidecarStoreEntry, error) {
	root := self.directory
	if directory := path.Dir(prefix); directory != "." {
		osPath, err := self.osPath(directory)
		if err != nil {
			return nil, err
		}
		root = osPath
	}
	entries := []SidecarStoreEntry{}
	walked := func(osPath string, entry fs.DirEntry, err error) error {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if osPath == self.tempDirectory {
			return fs.SkipDir
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(self.directory, osPath)
		if err != nil {
			return err
		}
		storePath := filepath.ToSlash(relative)
		if !strings.HasPrefix(storePath, prefix) {
			return nil
		}
		info, err := entry.Info()
		if errors.Is(err, fs.ErrNotExist) {
			// a file replaced or removed during the walk
			return nil
		}
		if err != nil {
			return err
		}
		entries = append(entries, SidecarStoreEntry{Name: storePath, ByteCount: info.Size()})
		return nil
	}
	if err := filepath.WalkDir(root, walked); err != nil {
		return nil, storeFault(err)
	}
	slices.SortFunc(entries, func(a SidecarStoreEntry, b SidecarStoreEntry) int {
		return strings.Compare(a.Name, b.Name)
	})
	return entries, nil
}

// Empties <state>/tmp. Each file is one a writer never finished: nothing renamed it out.
func (self *osStoreBackend) RemoveTemp() error {
	entries, err := os.ReadDir(self.tempDirectory)
	if err != nil {
		return storeFault(err)
	}
	for _, entry := range entries {
		err := os.Remove(filepath.Join(self.tempDirectory, entry.Name()))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return storeFault(err)
		}
	}
	return nil
}

// Opens the file at path 0600 at its end, or makes it, with its directories, when it is absent. An
// existing file opens first, so making one is the only step that can race another opener, which O_EXCL
// settles.
func (self *osStoreBackend) OpenAppend(storePath string) (SidecarStoreBackendAppendFile, bool, error) {
	osPath, err := self.osPath(storePath)
	if err != nil {
		return nil, false, err
	}
	file, err := os.OpenFile(osPath, os.O_WRONLY|os.O_APPEND, osBackendFileMode)
	if err == nil {
		return &osAppendFile{file: file}, false, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, false, storeFault(err)
	}
	if err := makeOsDirectory(filepath.Dir(osPath)); err != nil {
		return nil, false, err
	}
	file, err = os.OpenFile(osPath, os.O_WRONLY|os.O_APPEND|os.O_CREATE|os.O_EXCL, osBackendFileMode)
	if errors.Is(err, fs.ErrExist) {
		file, err = os.OpenFile(osPath, os.O_WRONLY|os.O_APPEND, osBackendFileMode)
		if err != nil {
			return nil, false, storeFault(err)
		}
		return &osAppendFile{file: file}, false, nil
	}
	if err != nil {
		return nil, false, storeFault(err)
	}
	return &osAppendFile{file: file}, true, nil
}

// A file opened O_APPEND, whose errors lose their path.
type osAppendFile struct {
	file   *os.File
	closed bool
}

// Appends p.
func (self *osAppendFile) Write(p []byte) (int, error) {
	n, err := self.file.Write(p)
	if err != nil {
		return n, storeFault(err)
	}
	return n, nil
}

// Stats the open file, so a rename over its path does not change the answer.
func (self *osAppendFile) Size() (int64, error) {
	info, err := self.file.Stat()
	if err != nil {
		return 0, storeFault(err)
	}
	return info.Size(), nil
}

// ftruncate, after which O_APPEND writes land at the new end.
func (self *osAppendFile) Truncate(byteCount int64) error {
	if err := self.file.Truncate(byteCount); err != nil {
		return storeFault(err)
	}
	return nil
}

// fsyncs the file, which on darwin is F_FULLFSYNC.
func (self *osAppendFile) Sync() error {
	if err := self.file.Sync(); err != nil {
		return storeFault(err)
	}
	return nil
}

// Closes the file once.
func (self *osAppendFile) Close() error {
	if self.closed {
		return nil
	}
	self.closed = true
	if err := self.file.Close(); err != nil {
		return storeFault(err)
	}
	return nil
}

// Makes directory and whatever is missing above it, fsyncing each new one's parent so a power cut
// cannot take a directory out from under a file renamed into it.
func makeOsDirectory(directory string) error {
	missing := []string{}
	for current := directory; ; current = filepath.Dir(current) {
		info, err := os.Stat(current)
		if err == nil {
			if !info.IsDir() {
				return ErrSidecarStoreFailed
			}
			break
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return storeFault(err)
		}
		missing = append(missing, current)
	}
	slices.Reverse(missing)
	for _, current := range missing {
		if err := os.Mkdir(current, osBackendDirectoryMode); err != nil && !errors.Is(err, fs.ErrExist) {
			return storeFault(err)
		}
		if err := syncOsDirectory(filepath.Dir(current)); err != nil {
			return err
		}
	}
	return nil
}

// A file open for reading, whose errors lose their path.
type osStoreReader struct {
	file *os.File
}

// Passes an end of file through as it is.
func (self *osStoreReader) Read(p []byte) (int, error) {
	n, err := self.file.Read(p)
	if err != nil && err != io.EOF {
		return n, storeFault(err)
	}
	return n, err
}

// Closes the file.
func (self *osStoreReader) Close() error {
	return self.file.Close()
}

// A temp file in <state>/tmp.
type osStoreFile struct {
	backend *osStoreBackend
	file    *os.File
	renamed bool
	dropped bool
}

// Appends p.
func (self *osStoreFile) Write(p []byte) (int, error) {
	n, err := self.file.Write(p)
	if err != nil {
		return n, storeFault(err)
	}
	return n, nil
}

// fsyncs the file, which on darwin is F_FULLFSYNC.
func (self *osStoreFile) Sync() error {
	if err := self.file.Sync(); err != nil {
		return storeFault(err)
	}
	return nil
}

// Closes first, since Windows renames no open file, and makes path's directories.
func (self *osStoreFile) Rename(storePath string) error {
	osPath, err := self.backend.osPath(storePath)
	if err != nil {
		return err
	}
	if err := self.file.Close(); err != nil {
		return storeFault(err)
	}
	if err := makeOsDirectory(filepath.Dir(osPath)); err != nil {
		return err
	}
	if err := os.Rename(self.file.Name(), osPath); err != nil {
		return storeFault(err)
	}
	self.renamed = true
	return nil
}

// Closes and removes the file, unless Rename took it.
func (self *osStoreFile) Discard() error {
	if self.renamed || self.dropped {
		return nil
	}
	self.dropped = true
	self.file.Close()
	if err := os.Remove(self.file.Name()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return storeFault(err)
	}
	return nil
}
