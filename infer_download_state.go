//go:build !ios_extension && !sidecar_http

// A local model file's state in a download's directory (DESIGN-COMPUTE §6.5's model downloads; CO-49, R-INFER-10,
// D-INFER-12). A file whose SHA-256 is <sha256> keeps, beside it:
//
//	<sha256>.index      its chunk index's bytes, kept once they passed the manifest's pin, and read again only
//	                    through that pin, so a changed copy is fetched again, never trusted
//	<sha256>.part       the file being downloaded, at its full size, each chunk written at its offset
//	<sha256>.part.done  the chunks done: one 16-byte record a chunk, appended and synced only once the chunk's bytes
//	                    are synced in the part, each record its chunk's number and a checksum binding it to the index
//	                    pin, so a torn last record, or one of another file's, is ignored and its chunk fetched again
//	<sha256>.whole      the whole mark: the file's size, its modification time and its pins, written once every chunk
//	                    is done and before the part takes the file's name
//	<sha256>            the whole file
//
// Nothing opens a part. OpenWhole opens only a whole file whose mark matches it, its size, its modification time and
// the manifest's pins. A whole file whose size or modification time differs from its mark, or one with no mark, is
// checked again chunk by chunk against its index before it opens; a chunk that fails returns the file to its part,
// that chunk not done and every chunk that passed done, so a fetch takes only what changed. There is no whole-file
// hash: the pinned index lists every chunk, so the chunks' checks are the file's (§6.5's whole row).
//
// Every step leaves a state a crash recovers from: a part with its done list resumes at the first chunk not done; a
// part whose mark is written finishes again; a whole file with no mark is checked again; a done list with no part is
// dropped. A part's size is set to the file's when it is opened, and the marks of chunks past what it held before are
// dropped, since their bytes are gone.
//
// The methods that end WithLock run with the file's slot held (InferModelDownload.takeSlot).

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
)

// The done list's records, one a chunk: its number, 8 bytes big-endian, then the first 8 bytes of SHA-256 over the
// records' domain, the index pin's 32 bytes and the number's 8, so a torn record, or one of another file or index,
// never passes. The widths of the list's layout.
const (
	inferModelDoneNumberByteCount   = 8
	inferModelDoneChecksumByteCount = 8
	inferModelDoneRecordByteCount   = inferModelDoneNumberByteCount + inferModelDoneChecksumByteCount
)

// The done records' checksum domain.
const inferModelDoneDomain = "urnetwork-sidecar-v1/model-chunk-done"

// The whole mark's format version.
const inferModelWholeMarkVersion = 1

// What a state file is named, beside the file's SHA-256.
const (
	inferModelIndexSuffix     = ".index"
	inferModelPartSuffix      = ".part"
	inferModelDoneSuffix      = ".part.done"
	inferModelWholeMarkSuffix = ".whole"
	// a state file being written whole, renamed into place once synced
	inferModelTempSuffix = ".tmp"
)

// The paths of one file's state.
type inferModelFilePaths struct {
	index string
	part  string
	done  string
	mark  string
	whole string
}

// The paths of the file whose SHA-256 is sha256, in directory.
func newInferModelFilePaths(directory string, sha256 string) *inferModelFilePaths {
	whole := filepath.Join(directory, sha256)
	return &inferModelFilePaths{
		index: whole + inferModelIndexSuffix,
		part:  whole + inferModelPartSuffix,
		done:  whole + inferModelDoneSuffix,
		mark:  whole + inferModelWholeMarkSuffix,
		whole: whole,
	}
}

// One local model file in a download's directory, by the manifest's pins: its whole file, which OpenWhole alone
// opens, and its part, which nothing opens. Safe for concurrent use: each method holds the file's slot.
type InferModelFile struct {
	download *InferModelDownload
	// the manifest's pins, a copy
	file *InferManifestModelFile
	// the index pin's bytes, which the done records bind
	pinDigest [sha256.Size]byte
	paths     *inferModelFilePaths
}

// The whole mark's content.
type inferModelWholeMark struct {
	Version         int    `json:"version"`
	Sha256          string `json:"sha256"`
	ByteCount       int64  `json:"byte_count"`
	IndexSha256     string `json:"index_sha256"`
	ModTimeUnixNano int64  `json:"mod_time_unix_nano"`
}

// Whether the mark is file's, and info, the whole file's, is what it was when marked.
func (self *inferModelWholeMark) matches(file *InferManifestModelFile, info fs.FileInfo) bool {
	return self.Version == inferModelWholeMarkVersion && self.Sha256 == file.Sha256 && self.ByteCount == file.ByteCount &&
		self.IndexSha256 == file.IndexSha256 && info.Mode().IsRegular() && info.Size() == file.ByteCount &&
		info.ModTime().UnixNano() == self.ModTimeUnixNano
}

// The record that marks chunk n done for the index whose pin is pinDigest.
func inferModelDoneRecord(pinDigest [sha256.Size]byte, n int) []byte {
	record := make([]byte, inferModelDoneRecordByteCount)
	binary.BigEndian.PutUint64(record[:inferModelDoneNumberByteCount], uint64(n))
	copy(record[inferModelDoneNumberByteCount:], inferModelDoneChecksum(pinDigest, record[:inferModelDoneNumberByteCount]))
	return record
}

// A record's checksum over its number's bytes.
func inferModelDoneChecksum(pinDigest [sha256.Size]byte, number []byte) []byte {
	hash := sha256.New()
	hash.Write([]byte(inferModelDoneDomain))
	hash.Write(pinDigest[:])
	hash.Write(number)
	return hash.Sum(nil)[:inferModelDoneChecksumByteCount]
}

// The chunks the done list at path marks, for an index of chunkCount chunks whose pin is pinDigest, and how long the
// list's whole records run, where a torn last record ends them. A list that is missing marks none; one longer than two
// records a chunk, which no download writes, is read as none, with a length of 0 so it is begun again.
func readInferModelDoneList(path string, pinDigest [sha256.Size]byte, chunkCount int) ([]bool, int64, error) {
	done := make([]bool, chunkCount)
	data, err := inferReadBoundedFile(path, int64(2*(chunkCount+1)*inferModelDoneRecordByteCount))
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, errInferStateFileTooLong) {
		return done, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	wholeLength := len(data) / inferModelDoneRecordByteCount * inferModelDoneRecordByteCount
	for at := 0; at < wholeLength; at += inferModelDoneRecordByteCount {
		record := data[at : at+inferModelDoneRecordByteCount]
		number := binary.BigEndian.Uint64(record[:inferModelDoneNumberByteCount])
		if uint64(chunkCount) <= number {
			continue
		}
		if !bytes.Equal(record[inferModelDoneNumberByteCount:], inferModelDoneChecksum(pinDigest, record[:inferModelDoneNumberByteCount])) {
			continue
		}
		done[number] = true
	}
	return done, int64(wholeLength), nil
}

// A state file past the length its reader holds it to.
var errInferStateFileTooLong = errors.New("model download: a state file past its bound")

// The file at path, refused with errInferStateFileTooLong past maxByteCount.
func inferReadBoundedFile(path string, maxByteCount int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, max(0, maxByteCount)+1))
	if err != nil {
		return nil, err
	}
	if max(0, maxByteCount) < int64(len(data)) {
		return nil, errInferStateFileTooLong
	}
	return data, nil
}

// Writes data to path whole: a temporary file beside it, synced, renamed over it, and the directory synced.
func inferWriteFileSynced(path string, data []byte) error {
	temp := path + inferModelTempSuffix
	file, err := os.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, err = file.Write(data)
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(temp, path)
	}
	if err != nil {
		os.Remove(temp)
		return err
	}
	return inferSyncDirectory(filepath.Dir(path))
}

// Syncs a directory, so a rename or a removal in it is durable. Windows opens no directory to sync, and NTFS journals
// the rename itself.
func inferSyncDirectory(directory string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	file, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}

// Removes path, which may be missing.
func inferRemoveIfExists(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// Where the whole file is, once whole: what a loader is given once OpenWhole answers.
func (self *InferModelFile) Path() string {
	return self.paths.whole
}

// The file's SHA-256.
func (self *InferModelFile) Sha256() string {
	return self.file.Sha256
}

// Opens the whole file to read, and only that: a file whose whole mark matches it, its size, its modification time and
// the manifest's pins. A whole file whose mark does not match it is checked again chunk by chunk against its kept
// index first: every chunk passing, it is marked again and opened; a chunk failing, or its size changed, it is
// returned to its part with what passed done, and refused. Refused with ErrInferModelNotWhole while a download of it
// runs, for a part or no file, and for a whole file whose mark does not match it when no index is kept to check it
// with, which a fetch then fetches. ctx bounds the check.
func (self *InferModelFile) OpenWhole(ctx context.Context) (*os.File, error) {
	release, ok := self.download.tryTakeSlot(self.file.Sha256)
	if !ok {
		return nil, fmt.Errorf("%w: a download of it is running", ErrInferModelNotWhole)
	}
	defer release()
	state, why, err := self.checkWholeWithLock(ctx, self.keptIndex)
	if err != nil {
		return nil, err
	}
	switch state {
	case inferModelWholeAbsent:
		return nil, fmt.Errorf("%w: it is not downloaded whole", ErrInferModelNotWhole)
	case inferModelWholeUnchecked:
		return nil, fmt.Errorf("%w: it changed since it was marked whole, and its index must be fetched to check it", ErrInferModelNotWhole)
	case inferModelWholeReturned:
		return nil, fmt.Errorf("%w: %s, so it was returned to its part for a fetch", ErrInferModelNotWhole, why)
	}
	opened, err := os.Open(self.paths.whole)
	if err != nil {
		return nil, err
	}
	// what was opened is what the mark names, whatever moved between the check and the open
	info, err := opened.Stat()
	mark := self.readMark()
	if err != nil || mark == nil || !mark.matches(self.file, info) {
		opened.Close()
		return nil, fmt.Errorf("%w: it changed as it was opened", ErrInferModelNotWhole)
	}
	return opened, nil
}

// Deletes every state of the file: its mark first, so nothing between is taken for whole, then its whole file, its
// part, its done list and its kept index, waiting for a download of it to end. ctx bounds the wait.
func (self *InferModelFile) Remove(ctx context.Context) error {
	release, err := self.download.takeSlot(ctx, self.file.Sha256)
	if err != nil {
		return err
	}
	defer release()
	for _, path := range []string{self.paths.mark, self.paths.whole, self.paths.part, self.paths.done, self.paths.index} {
		if err := inferRemoveIfExists(path); err != nil {
			return err
		}
		if err := inferRemoveIfExists(path + inferModelTempSuffix); err != nil {
			return err
		}
	}
	if err := inferSyncDirectory(self.download.directory); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// The index kept beside the file, or nil where none is kept or it fails its pin, which ParseInferModelIndex checks
// again at every read.
func (self *InferModelFile) keptIndex() *InferModelIndex {
	settings := self.download.settings
	data, err := inferReadBoundedFile(self.paths.index, int64(max(0, settings.ModelIndexMaxByteCount)))
	if err != nil {
		return nil
	}
	index, err := ParseInferModelIndex(data, self.file, settings)
	if err != nil {
		self.download.log.Warningf("[infer_download]%s's kept index is refused, so it is fetched again: %s\n", self.file.Sha256, err)
		return nil
	}
	return index
}

// Keeps index beside the file.
func (self *InferModelFile) keepIndexWithLock(index *InferModelIndex) error {
	if err := inferWriteFileSynced(self.paths.index, index.Bytes()); err != nil {
		return fmt.Errorf("model download: keeping the index: %w", err)
	}
	testHookBarrier("infer_download.index.kept", self.file.Sha256)
	return nil
}

// The whole mark, or nil where there is none or it does not read.
func (self *InferModelFile) readMark() *inferModelWholeMark {
	// a mark is far shorter than an index, so one past an index's bound is none
	data, err := inferReadBoundedFile(self.paths.mark, int64(max(0, self.download.settings.ModelIndexMaxByteCount)))
	if err != nil {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	mark := &inferModelWholeMark{}
	if err := decoder.Decode(mark); err != nil {
		return nil
	}
	return mark
}

// Writes the whole mark of the file info describes, synced.
func (self *InferModelFile) writeMarkWithLock(info fs.FileInfo) error {
	data, err := json.Marshal(&inferModelWholeMark{
		Version:         inferModelWholeMarkVersion,
		Sha256:          self.file.Sha256,
		ByteCount:       self.file.ByteCount,
		IndexSha256:     self.file.IndexSha256,
		ModTimeUnixNano: info.ModTime().UnixNano(),
	})
	if err != nil {
		return err
	}
	if err := inferWriteFileSynced(self.paths.mark, data); err != nil {
		return fmt.Errorf("model download: writing the whole mark: %w", err)
	}
	return nil
}

// What checkWholeWithLock found.
type inferModelWholeState int

const (
	// no whole file
	inferModelWholeAbsent inferModelWholeState = iota
	// whole, its mark matching it: the one state OpenWhole opens
	inferModelWholeMarked
	// a whole file its mark does not match, not checked for want of an index
	inferModelWholeUnchecked
	// checked again, a chunk failing or its size changed, and returned to its part
	inferModelWholeReturned
)

// The whole file's state: absent; marked, as it is or once every chunk passed its check again, when it is marked
// anew; unchecked where its mark does not match it and index gives none; or returned to its part, with why.
func (self *InferModelFile) checkWholeWithLock(ctx context.Context, index func() *InferModelIndex) (inferModelWholeState, string, error) {
	info, err := os.Lstat(self.paths.whole)
	if errors.Is(err, fs.ErrNotExist) {
		return inferModelWholeAbsent, "", nil
	}
	if err != nil {
		return 0, "", err
	}
	if !info.Mode().IsRegular() {
		return 0, "", fmt.Errorf("model download: %s is no regular file", self.file.Sha256)
	}
	if mark := self.readMark(); mark != nil && mark.matches(self.file, info) {
		return inferModelWholeMarked, "", nil
	}
	checked := index()
	if checked == nil {
		return inferModelWholeUnchecked, "", nil
	}
	failing, err := self.recheck(ctx, checked, info.Size())
	if err != nil {
		return 0, "", err
	}
	if len(failing) == 0 && info.Size() == self.file.ByteCount {
		// every chunk passed: marked anew, as the file is now
		if err := self.writeMarkWithLock(info); err != nil {
			return 0, "", err
		}
		return inferModelWholeMarked, "", nil
	}
	if err := self.returnToPartWithLock(checked, failing, info.Size()); err != nil {
		return 0, "", err
	}
	if len(failing) == 0 {
		return inferModelWholeReturned, "its size changed since it was marked whole", nil
	}
	return inferModelWholeReturned, fmt.Sprintf("its chunk %d changed since it was marked whole", failing[0]), nil
}

// The chunks of the whole file that fail their check against index, in order: those it does not hold whole at its
// size of byteCount, and those whose bytes are not their hash's. It reads the file once, through a hash, holding no
// chunk.
func (self *InferModelFile) recheck(ctx context.Context, index *InferModelIndex, byteCount int64) ([]int, error) {
	file, err := os.Open(self.paths.whole)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	failing := []int{}
	hash := sha256.New()
	for n := 0; n < index.ChunkCount(); n += 1 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		chunk, _ := index.Chunk(n)
		if byteCount < chunk.Offset+chunk.ByteCount {
			failing = append(failing, n)
			continue
		}
		hash.Reset()
		if _, err := io.Copy(hash, io.NewSectionReader(file, chunk.Offset, chunk.ByteCount)); err != nil {
			return nil, err
		}
		if [sha256.Size]byte(hash.Sum(nil)) != chunk.digest {
			failing = append(failing, n)
		}
	}
	return failing, nil
}

// Returns the whole file to its part, every chunk done but failing: its mark removed first, so it is not whole from
// then on; any part beside it removed, which would be paired with this file's list; the list written whole; the file
// sized to the manifest's; then renamed to the part.
func (self *InferModelFile) returnToPartWithLock(index *InferModelIndex, failing []int, byteCount int64) error {
	if err := inferRemoveIfExists(self.paths.mark); err != nil {
		return err
	}
	if err := inferRemoveIfExists(self.paths.part); err != nil {
		return err
	}
	records := []byte{}
	for n := 0; n < index.ChunkCount(); n += 1 {
		if !slices.Contains(failing, n) {
			records = append(records, inferModelDoneRecord(self.pinDigest, n)...)
		}
	}
	if err := inferWriteFileSynced(self.paths.done, records); err != nil {
		return err
	}
	if byteCount != self.file.ByteCount {
		if err := os.Truncate(self.paths.whole, self.file.ByteCount); err != nil {
			return err
		}
	}
	if err := os.Rename(self.paths.whole, self.paths.part); err != nil {
		return err
	}
	if err := inferSyncDirectory(self.download.directory); err != nil {
		return err
	}
	testHookBarrier("infer_download.whole.returned", self.file.Sha256)
	return nil
}

// Removes what a crash between a whole file's rename and its cleanup left: a part and its done list.
func (self *InferModelFile) removePartWithLock() error {
	if err := inferRemoveIfExists(self.paths.part); err != nil {
		return err
	}
	return inferRemoveIfExists(self.paths.done)
}

// The bytes of the chunks the done list marks, within what the part holds, for the room a fetch needs; 0 with no
// part.
func (self *InferModelFile) doneByteCountWithLock(index *InferModelIndex) (int64, error) {
	info, err := os.Stat(self.paths.part)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	done, _, err := readInferModelDoneList(self.paths.done, self.pinDigest, index.ChunkCount())
	if err != nil {
		return 0, err
	}
	byteCount := int64(0)
	for n, isDone := range done {
		chunk, _ := index.Chunk(n)
		if isDone && chunk.Offset+chunk.ByteCount <= info.Size() {
			byteCount += chunk.ByteCount
		}
	}
	return byteCount, nil
}

// Opens the part and its done list for the run: a part made at the file's size where there is none, its done list
// dropped then, since a list without its part means nothing; a part of another size sized to the file's, the marks of
// chunks past what it held dropped and the list written again without them; a torn last record cut off. Then the
// chunks not done, in order.
func (self *inferDownloadRun) openPart() error {
	paths := self.modelFile.paths
	info, err := os.Stat(paths.part)
	existed := err == nil
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if !existed {
		if err := inferRemoveIfExists(paths.done); err != nil {
			return err
		}
	}
	part, err := os.OpenFile(paths.part, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("model download: opening the part: %w", err)
	}
	self.part = part
	heldByteCount := int64(0)
	if existed {
		heldByteCount = info.Size()
	}
	if heldByteCount != self.file.ByteCount {
		if err := part.Truncate(self.file.ByteCount); err != nil {
			return fmt.Errorf("model download: sizing the part: %w", err)
		}
	}

	done, wholeLength, err := readInferModelDoneList(paths.done, self.modelFile.pinDigest, self.index.ChunkCount())
	if err != nil {
		return fmt.Errorf("model download: reading the done list: %w", err)
	}
	dropped := false
	for n := range done {
		chunk, _ := self.index.Chunk(n)
		if done[n] && heldByteCount < chunk.Offset+chunk.ByteCount {
			done[n] = false
			dropped = true
		}
	}
	if dropped {
		records := []byte{}
		for n, isDone := range done {
			if isDone {
				records = append(records, inferModelDoneRecord(self.modelFile.pinDigest, n)...)
			}
		}
		if err := inferWriteFileSynced(paths.done, records); err != nil {
			return err
		}
		wholeLength = int64(len(records))
	}
	// a torn last record goes, so the next record starts at a record's boundary: cut by its path, since a file open to
	// append alone may not be cut (Windows), and made durable by the next record's sync
	if doneInfo, err := os.Stat(paths.done); err == nil && doneInfo.Size() != wholeLength {
		if err := os.Truncate(paths.done, wholeLength); err != nil {
			return fmt.Errorf("model download: cutting a torn record: %w", err)
		}
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	doneList, err := os.OpenFile(paths.done, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("model download: opening the done list: %w", err)
	}
	self.doneList = doneList

	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.done = done
	for n, isDone := range done {
		chunk, _ := self.index.Chunk(n)
		if isDone {
			self.doneChunkCount += 1
			self.doneByteCount += chunk.ByteCount
		} else {
			self.missing = append(self.missing, n)
		}
	}
	return nil
}

// Makes the part whole once every chunk is done: the part and the list closed, the part's size checked, the mark
// written with the part's size and modification time and synced, then the part renamed to the whole file and the list
// removed. A crash after the mark finishes it again from the part; one after the rename leaves it whole.
func (self *inferDownloadRun) finish() error {
	paths := self.modelFile.paths
	if err := self.closeFiles(); err != nil {
		return err
	}
	info, err := os.Stat(paths.part)
	if err != nil {
		return err
	}
	if info.Size() != self.file.ByteCount {
		return fmt.Errorf("model download: the part of %s holds %d bytes, not %d", self.file.Sha256, info.Size(), self.file.ByteCount)
	}
	if err := self.modelFile.writeMarkWithLock(info); err != nil {
		return err
	}
	testHookBarrier("infer_download.whole.marked", self.file.Sha256)
	if err := os.Rename(paths.part, paths.whole); err != nil {
		return fmt.Errorf("model download: making the part whole: %w", err)
	}
	if err := inferSyncDirectory(self.download.directory); err != nil {
		return err
	}
	testHookBarrier("infer_download.whole.renamed", self.file.Sha256)
	return inferRemoveIfExists(paths.done)
}

// Closes the part and its done list, where open.
func (self *inferDownloadRun) closeFiles() error {
	var err error
	if self.part != nil {
		err = self.part.Close()
		self.part = nil
	}
	if self.doneList != nil {
		if closeErr := self.doneList.Close(); err == nil {
			err = closeErr
		}
		self.doneList = nil
	}
	return err
}
