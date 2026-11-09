// An edge's local snapshot (§12.6): the view it serves, kept on disk so a restart serves through a core
// outage, beside the key window and the lb interfaces the feed last named (plan reading 6), since
// neither reaches an edge any other way. Each root has a directory of its own:
//
//   - snapshot.ndjson, the current one: wire.go's snapshot lines, its first line widened with the
//     window and the interfaces;
//   - replaced-<replaced serial>-<serial>.ndjson, a snapshot a reload across a restore replaced, with
//     its diff and the reload's time in the first line, kept only until POST /dns/reload-diff takes the
//     diff and at most feed.replaced_keep_s (§2.8 dns-1's 24 h);
//   - *.tmp, a write in progress, which a crash may leave and opening removes.
//
// Every write goes to a temporary file, is fsynced, renamed over its place and the directory fsynced,
// so a crash at any point leaves the old file or the new one whole, and a reader sees a consistent
// serial. A file that does not read whole is refused, and the edge discards it and stays not ready.
// Safe for concurrent use: one lock serializes every change to the directory.

package dnsservice

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The names in a root's directory.
const (
	dnsSnapshotFileName        = "snapshot.ndjson"
	dnsReplacedFilePrefix      = "replaced-"
	dnsSnapshotFileSuffix      = ".ndjson"
	dnsSnapshotTemporarySuffix = ".tmp"
)

// Owner-only, for the directory and its files: the zone is public, but the files are the edge's.
const (
	dnsSnapshotDirectoryMode = 0o700
	dnsSnapshotFileMode      = 0o600
)

// The first line of a local file: the wire's snapshot line and what an edge keeps beside it. Readers of
// the wire's line ignore the rest, as N ignores what N+1 adds.
type dnsSnapshotFileHeader struct {
	DnsSnapshot
	KeyWindow  *DnsKeyWindow    `json:"key_window,omitempty"`
	Interfaces []DnsLbInterface `json:"interfaces,omitempty"`
	// A replaced file's: the diff it was kept for and when its reload happened.
	Diff       *DnsReloadDiff `json:"diff,omitempty"`
	ReloadTime time.Time      `json:"reload_time,omitzero"`
}

// What a local snapshot holds.
type DnsSavedSnapshot struct {
	View          *ZoneView
	RestoreSerial uint64
	// nil when none was saved with it.
	KeyWindow  *DnsKeyWindow
	Interfaces []DnsLbInterface
}

// A replaced snapshot waiting for its diff to be taken.
type DnsReplacedSnapshot struct {
	Diff       *DnsReloadDiff
	ReloadTime time.Time
	path       string
}

// One root's local files.
type SnapshotFile struct {
	directory string
	root      string

	stateLock sync.Mutex
}

// The files of root under directory, made when missing. A write a crash left half done is removed.
func NewSnapshotFile(directory string, root string) (*SnapshotFile, error) {
	if err := validateDnsRoot(root); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(directory, dnsSnapshotDirectoryMode); err != nil {
		return nil, err
	}
	temporaries, err := filepath.Glob(filepath.Join(directory, "*"+dnsSnapshotTemporarySuffix))
	if err != nil {
		return nil, err
	}
	for _, temporary := range temporaries {
		if err := os.Remove(temporary); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
	}
	return &SnapshotFile{directory: directory, root: root}, nil
}

// The current snapshot as a view under settings, or an error wrapping fs.ErrNotExist when there is
// none. Any other error means the file does not read whole, and nothing of it may serve.
func (self *SnapshotFile) Load(settings *DnsSettings) (*DnsSavedSnapshot, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	header, view, err := self.readWithLock(filepath.Join(self.directory, dnsSnapshotFileName), settings)
	if err != nil {
		return nil, err
	}
	return &DnsSavedSnapshot{
		View:          view,
		RestoreSerial: header.RestoreSerial,
		KeyWindow:     header.KeyWindow,
		Interfaces:    header.Interfaces,
	}, nil
}

// Reads one file whole. settings nil reads only its first line.
func (self *SnapshotFile) readWithLock(path string, settings *DnsSettings) (*dnsSnapshotFileHeader, *ZoneView, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()
	reader := bufio.NewReaderSize(file, 64*1024)
	line, err := readDnsSnapshotLine(reader)
	if err != nil {
		return nil, nil, err
	}
	header := &dnsSnapshotFileHeader{}
	if err := json.Unmarshal(line, header); err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrDnsRowMalformed, err)
	}
	if err := checkDnsFormat(header.Format); err != nil {
		return nil, nil, err
	}
	if header.Root != self.root {
		return nil, nil, fmt.Errorf("%w: a snapshot of %s in %s's place", ErrDnsRowMalformed, header.Root, self.root)
	}
	if settings == nil {
		return header, nil, nil
	}
	rows, err := NewDnsSnapshotReader(io.MultiReader(bytes.NewReader(append(line, '\n')), reader))
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	view, err := NewZoneView(settings, rows)
	if err != nil {
		return nil, nil, err
	}
	// NewZoneView stops at the rows' end, so this reads the end line and refuses anything past it
	if _, err := rows.Next(); !errors.Is(err, io.EOF) {
		return nil, nil, fmt.Errorf("%w: a snapshot that does not end", ErrDnsRowMalformed)
	}
	return header, view, nil
}

// One line, at most a snapshot line's bound, without its newline.
func readDnsSnapshotLine(reader *bufio.Reader) ([]byte, error) {
	line := []byte{}
	for {
		chunk, isPrefix, err := reader.ReadLine()
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrDnsRowMalformed, err)
		}
		line = append(line, chunk...)
		if dnsSnapshotLineMaxByteCount < len(line) {
			return nil, fmt.Errorf("%w: a line past the bound", ErrDnsRowMalformed)
		}
		if !isPrefix {
			return line, nil
		}
	}
}

// Writes path whole: a temporary file, fsynced, renamed over path, and the directory fsynced. The
// barriers hold a write before it starts, between its fsync and its rename, where a crash leaves the
// old file whole, and after.
func (self *SnapshotFile) writeWithLock(path string, header *dnsSnapshotFileHeader, view *ZoneView) error {
	testHookBarrier("dnsservice.snapshot_write.before", "")
	temporary := path + dnsSnapshotTemporarySuffix
	err := func() error {
		file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, dnsSnapshotFileMode)
		if err != nil {
			return err
		}
		defer file.Close()
		buffered := bufio.NewWriterSize(file, 64*1024)
		line, err := json.Marshal(header)
		if err != nil {
			return err
		}
		if _, err := buffered.Write(append(line, '\n')); err != nil {
			return err
		}
		writer := &DnsSnapshotWriter{writer: buffered}
		for set := range view.Rows() {
			if err := writer.Write(set); err != nil {
				return err
			}
		}
		if err := writer.Close(); err != nil {
			return err
		}
		if err := buffered.Flush(); err != nil {
			return err
		}
		return file.Sync()
	}()
	if err != nil {
		os.Remove(temporary)
		return err
	}
	testHookBarrier("dnsservice.snapshot_write", "")
	if err := os.Rename(temporary, path); err != nil {
		os.Remove(temporary)
		return err
	}
	if err := self.syncDirectoryWithLock(); err != nil {
		return err
	}
	testHookBarrier("dnsservice.snapshot_write.after", "")
	return nil
}

// fsyncs the directory, so a rename survives a crash.
func (self *SnapshotFile) syncDirectoryWithLock() error {
	directory, err := os.Open(self.directory)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

// Writes view as the current snapshot, beside restoreSerial, the window and the interfaces, replacing
// what was there whole.
func (self *SnapshotFile) Save(view *ZoneView, restoreSerial uint64, keyWindow *DnsKeyWindow, interfaces []DnsLbInterface) error {
	if view.root != self.root {
		return fmt.Errorf("%w: a view of %s in %s's place", ErrDnsRowMalformed, view.root, self.root)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	header := &dnsSnapshotFileHeader{
		DnsSnapshot: DnsSnapshot{Format: DnsFormat, Root: self.root, Serial: view.serial, RestoreSerial: restoreSerial},
		KeyWindow:   keyWindow,
		Interfaces:  slices.Clone(interfaces),
	}
	return self.writeWithLock(filepath.Join(self.directory, dnsSnapshotFileName), header, view)
}

// Removes the current snapshot, as an edge does with one that did not read whole.
func (self *SnapshotFile) Discard() error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if err := os.Remove(filepath.Join(self.directory, dnsSnapshotFileName)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return self.syncDirectoryWithLock()
}

// Keeps replaced, the view a reload across a restore replaced, with its diff and the reload's time,
// until DeleteReplaced: dns-1's replaced snapshot.
func (self *SnapshotFile) KeepReplaced(replaced *ZoneView, diff *DnsReloadDiff, reloadTime time.Time) (*DnsReplacedSnapshot, error) {
	if replaced.root != self.root || diff.Root != self.root {
		return nil, fmt.Errorf("%w: a replaced view of another root", ErrDnsRowMalformed)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	name := dnsReplacedFilePrefix + strconv.FormatUint(diff.ReplacedSerial, 10) + "-" + strconv.FormatUint(diff.Serial, 10) + dnsSnapshotFileSuffix
	path := filepath.Join(self.directory, name)
	header := &dnsSnapshotFileHeader{
		DnsSnapshot: DnsSnapshot{Format: DnsFormat, Root: self.root, Serial: replaced.serial},
		Diff:        diff,
		ReloadTime:  reloadTime,
	}
	if err := self.writeWithLock(path, header, replaced); err != nil {
		return nil, err
	}
	return &DnsReplacedSnapshot{Diff: diff, ReloadTime: reloadTime, path: path}, nil
}

// Every replaced snapshot kept, by the diff it waits on, oldest reload first. One whose first line does
// not read is removed, since its diff cannot be posted.
func (self *SnapshotFile) Replaced() ([]*DnsReplacedSnapshot, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	paths, err := filepath.Glob(filepath.Join(self.directory, dnsReplacedFilePrefix+"*"+dnsSnapshotFileSuffix))
	if err != nil {
		return nil, err
	}
	replaced := []*DnsReplacedSnapshot{}
	for _, path := range paths {
		header, _, err := self.readWithLock(path, nil)
		if err != nil || header.Diff == nil || header.Diff.Root != self.root || header.ReloadTime.IsZero() {
			if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return nil, err
			}
			continue
		}
		replaced = append(replaced, &DnsReplacedSnapshot{Diff: header.Diff, ReloadTime: header.ReloadTime, path: path})
	}
	slices.SortFunc(replaced, func(a *DnsReplacedSnapshot, b *DnsReplacedSnapshot) int {
		return a.ReloadTime.Compare(b.ReloadTime)
	})
	return replaced, nil
}

// Removes a replaced snapshot once its diff is taken or its time is up.
func (self *SnapshotFile) DeleteReplaced(replaced *DnsReplacedSnapshot) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if !strings.HasPrefix(filepath.Base(replaced.path), dnsReplacedFilePrefix) {
		return fmt.Errorf("%w: not a replaced snapshot", ErrDnsRowMalformed)
	}
	if err := os.Remove(replaced.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return self.syncDirectoryWithLock()
}
