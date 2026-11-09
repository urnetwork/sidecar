// The append-only sealed log (state_log.go): durability before an append returns, torn tails dropped, and every
// other fault Failed, never the end of the log.

package sidecar

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// The crash world models no appends: the keychain's own kills never reach a log. state_log_test.go's
// logFaultBackend is the log's medium.
func (self *crashBackend) OpenAppend(filePath string) (SidecarStoreBackendAppendFile, bool, error) {
	return nil, false, errors.New("the crash world models no appends")
}

// A memory medium whose appended files can lose what was never fsynced, as a power cut does, and whose Syncs can
// fail. Safe for concurrent use.
type logFaultBackend struct {
	SidecarStoreBackend
	stateLock sync.Mutex
	// each appended path's length at its last Sync
	syncedByteCounts map[string]int64
	// appended paths an append made whose directory is not synced yet, which a power cut takes
	unnamedPaths map[string]bool
	// the Sync, counting from 1, that fails; 0 fails none
	failSyncAt int
	syncCount  int
	// every call, in order, for a test of the steps
	trace []string
}

// Over memory, failing nothing.
func newLogFaultBackend() *logFaultBackend {
	return &logFaultBackend{
		SidecarStoreBackend: NewSidecarMemoryBackend(),
		syncedByteCounts:    map[string]int64{},
		unnamedPaths:        map[string]bool{},
	}
}

// The syncCount-th Sync from here fails.
func (self *logFaultBackend) failSync(syncCount int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.failSyncAt = self.syncCount + syncCount
}

// Notes a step.
func (self *logFaultBackend) note(step string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.trace = append(self.trace, step)
}

// The steps since the last call.
func (self *logFaultBackend) takeTrace() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	trace := self.trace
	self.trace = nil
	return trace
}

// Whether this Sync fails.
func (self *logFaultBackend) takeSync() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.syncCount += 1
	return self.syncCount == self.failSyncAt
}

// An appender whose Sync the backend steers.
func (self *logFaultBackend) OpenAppend(path string) (SidecarStoreBackendAppendFile, bool, error) {
	file, created, err := self.SidecarStoreBackend.OpenAppend(path)
	if err != nil {
		return nil, false, err
	}
	self.note("open")
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if created {
		self.syncedByteCounts[path] = 0
		self.unnamedPaths[path] = true
	} else if _, ok := self.syncedByteCounts[path]; !ok {
		size, err := file.Size()
		if err != nil {
			return nil, false, err
		}
		self.syncedByteCounts[path] = size
	}
	return &logFaultFile{SidecarStoreBackendAppendFile: file, backend: self, path: path}, created, nil
}

// Marks a new file's name durable.
func (self *logFaultBackend) SyncDirectory(path string) error {
	self.note("sync directory")
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.unnamedPaths, path)
	return self.SidecarStoreBackend.SyncDirectory(path)
}

// A power cut in the worst case: every appended file goes back to its last Sync, and one whose name was never
// synced is gone.
func (self *logFaultBackend) powerCut(t *testing.T) {
	t.Helper()
	self.stateLock.Lock()
	byteCounts := map[string]int64{}
	for path, byteCount := range self.syncedByteCounts {
		byteCounts[path] = byteCount
		if self.unnamedPaths[path] {
			byteCounts[path] = -1
		}
	}
	self.syncedByteCounts = map[string]int64{}
	self.unnamedPaths = map[string]bool{}
	self.stateLock.Unlock()
	for path, byteCount := range byteCounts {
		if byteCount < 0 {
			if err := self.SidecarStoreBackend.Remove(path); err != nil {
				t.Fatal(err)
			}
			continue
		}
		file, _, err := self.SidecarStoreBackend.OpenAppend(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Truncate(byteCount); err != nil {
			t.Fatal(err)
		}
		file.Close()
	}
}

// One appender on a logFaultBackend.
type logFaultFile struct {
	SidecarStoreBackendAppendFile
	backend *logFaultBackend
	path    string
}

// Notes the write.
func (self *logFaultFile) Write(p []byte) (int, error) {
	self.backend.note("write")
	return self.SidecarStoreBackendAppendFile.Write(p)
}

// Notes the cut.
func (self *logFaultFile) Truncate(byteCount int64) error {
	self.backend.note("truncate")
	return self.SidecarStoreBackendAppendFile.Truncate(byteCount)
}

// Fails when armed, keeping the bytes unsynced; otherwise makes them durable.
func (self *logFaultFile) Sync() error {
	self.backend.note("sync")
	if self.backend.takeSync() {
		return fmt.Errorf("%w: an injected fsync fault", ErrSidecarStoreFailed)
	}
	size, err := self.SidecarStoreBackendAppendFile.Size()
	if err != nil {
		return err
	}
	self.backend.stateLock.Lock()
	defer self.backend.stateLock.Unlock()
	self.backend.syncedByteCounts[self.path] = size
	return nil
}

// Locks and unlocks instance, so the next append reads its log afresh: a new keychain caches no tail. A test that
// changes a log's bytes behind an append does this, as nothing but the log's own appends change them in use.
func relockTestInstance(t *testing.T, instance *SidecarInstance) {
	t.Helper()
	instance.Lock()
	if err := instance.Unlock(nil); err != nil {
		t.Fatal(err)
	}
}

// An unlocked instance with testNetworkId enrolled on backend, and the log at name in class approval.
func openTestLog(t *testing.T, backend SidecarStoreBackend, name string) (*SidecarInstance, SidecarStoreLog) {
	t.Helper()
	instance := newInstanceOn(t, backend, newFakeKeyStore())
	if err := instance.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	enrollTestNetwork(t, instance, testNetworkId)
	log, err := OpenSidecarStoreLog(storeOf(t, instance, testNetworkId, "approval"), name)
	if err != nil {
		t.Fatal(err)
	}
	return instance, log
}

// Every record of log, which must read.
func readTestLog(t *testing.T, log SidecarStoreLog) [][]byte {
	t.Helper()
	records, err := readLogRecords(log)
	if err != nil {
		t.Fatal(err)
	}
	return records
}

// Every record of log, or what stopped the read.
func readLogRecords(log SidecarStoreLog) ([][]byte, error) {
	records := [][]byte{}
	err := log.Read(func(index uint64, record []byte) error {
		if index != uint64(len(records)) {
			return fmt.Errorf("index %d after %d records", index, len(records))
		}
		records = append(records, record)
		return nil
	})
	return records, err
}

// Fails unless records are want, in order.
func requireRecords(t *testing.T, records [][]byte, want ...string) {
	t.Helper()
	if len(records) != len(want) {
		t.Fatalf("%d records, want %d", len(records), len(want))
	}
	for i := range want {
		if string(records[i]) != want[i] {
			t.Errorf("record %d is %q, want %q", i, records[i], want[i])
		}
	}
}

// Appends each record, which must take.
func appendTestRecords(t *testing.T, log SidecarStoreLog, records ...string) {
	t.Helper()
	for _, record := range records {
		if err := log.Append([]byte(record)); err != nil {
			t.Fatal(err)
		}
	}
}

// The log file's bytes on backend.
func testLogPath(name string) string {
	return networkFilePath(testNetworkId, "approval/"+name)
}

func TestLogRoundTrip(t *testing.T) {
	_, log := openTestLog(t, NewSidecarMemoryBackend(), "a")
	if _, err := readLogRecords(log); !errors.Is(err, ErrSidecarStoreAbsent) {
		t.Fatalf("a log never appended to reads %v", err)
	}
	appendTestRecords(t, log, "one", "", "three")
	requireRecords(t, readTestLog(t, log), "one", "", "three")
}

// No plaintext reaches the medium, and each record seals under its own nonce.
func TestLogSealsEachRecord(t *testing.T) {
	backend := NewSidecarMemoryBackend()
	_, log := openTestLog(t, backend, "a")
	appendTestRecords(t, log, "synthetic record", "synthetic record")
	content := readBackend(t, backend, testLogPath("a"))
	if bytes.Contains(content, []byte("synthetic record")) {
		t.Error("plaintext on the medium")
	}
	if !bytes.HasPrefix(content, []byte(storeLogMagic)) {
		t.Error("no log header")
	}
}

// Append returns only after its fsync, and a new file's directory sync after that; a failed fsync fails the
// append, and a power cut then leaves the log without it.
func TestAppendDurableBeforeReturn(t *testing.T) {
	backend := newLogFaultBackend()
	_, log := openTestLog(t, backend, "a")
	backend.takeTrace()
	appendTestRecords(t, log, "first")
	trace := strings.Join(backend.takeTrace(), ",")
	if trace != "open,write,sync,sync directory" {
		t.Errorf("first append took %s", trace)
	}
	appendTestRecords(t, log, "second")
	if trace := strings.Join(backend.takeTrace(), ","); trace != "open,write,sync" {
		t.Errorf("second append took %s", trace)
	}

	backend.failSync(1)
	if err := log.Append([]byte("third")); err == nil {
		t.Fatal("an append whose fsync failed answered nil")
	}
	backend.powerCut(t)
	requireRecords(t, readTestLog(t, log), "first", "second")
	appendTestRecords(t, log, "fourth")
	requireRecords(t, readTestLog(t, log), "first", "second", "fourth")
}

// A kill at each fsync of a run of appends: what reads afterward is every record whose append returned nil, in the
// worst case, and the next append goes on from there.
func TestKillAtEachFsync(t *testing.T) {
	records := []string{"a", "bb", "ccc", "dddd"}
	for failAt := 1; failAt <= len(records); failAt += 1 {
		backend := newLogFaultBackend()
		_, log := openTestLog(t, backend, "a")
		backend.failSync(failAt)
		taken := []string{}
		for _, record := range records {
			if err := log.Append([]byte(record)); err != nil {
				break
			}
			taken = append(taken, record)
		}
		if len(taken) != failAt-1 {
			t.Fatalf("fsync %d: %d appends answered nil", failAt, len(taken))
		}
		backend.powerCut(t)
		read, err := readLogRecords(log)
		if errors.Is(err, ErrSidecarStoreAbsent) && len(taken) == 0 {
			// the first append's file, whose name the cut took with it
			read, err = [][]byte{}, nil
		}
		if err != nil {
			t.Fatal(err)
		}
		requireRecords(t, read, taken...)
		appendTestRecords(t, log, "after")
		requireRecords(t, readTestLog(t, log), append(taken, "after")...)
	}
}

// A tail cut anywhere inside the last record, or inside the header of a first record, reads as the records before
// it, and the next append cuts it off.
func TestTornTailDropped(t *testing.T) {
	backend := NewSidecarMemoryBackend()
	instance, log := openTestLog(t, backend, "a")
	appendTestRecords(t, log, "kept")
	keptByteCount := len(readBackend(t, backend, testLogPath("a")))
	appendTestRecords(t, log, "torn record")
	whole := readBackend(t, backend, testLogPath("a"))
	for cut := 0; cut < len(whole); cut += 1 {
		putBackendFile(t, backend, testLogPath("a"), whole[:cut])
		relockTestInstance(t, instance)
		fresh, err := OpenSidecarStoreLog(storeOf(t, instance, testNetworkId, "approval"), "a")
		if err != nil {
			t.Fatal(err)
		}
		want := []string{}
		if keptByteCount <= cut {
			want = []string{"kept"}
		}
		requireRecords(t, readTestLog(t, fresh), want...)
		appendTestRecords(t, fresh, "next")
		requireRecords(t, readTestLog(t, fresh), append(want, "next")...)
	}
}

// Zero bytes past the last record, as a medium that extended a length and never wrote it shows, are a torn tail.
func TestZeroTailDropped(t *testing.T) {
	backend := NewSidecarMemoryBackend()
	_, log := openTestLog(t, backend, "a")
	appendTestRecords(t, log, "kept")
	content := readBackend(t, backend, testLogPath("a"))
	for _, zeroByteCount := range []int{1, 7, 8, 9, 100} {
		putBackendFile(t, backend, testLogPath("a"), append(bytes.Clone(content), make([]byte, zeroByteCount)...))
		requireRecords(t, readTestLog(t, log), "kept")
	}
	putBackendFile(t, backend, testLogPath("a"), make([]byte, 40))
	requireRecords(t, readTestLog(t, log))
}

// A whole record that fails, in the middle or last, is Failed, never the end of the log.
func TestMiddleRecordCorruptIsFailed(t *testing.T) {
	backend := NewSidecarMemoryBackend()
	instance, log := openTestLog(t, backend, "a")
	appendTestRecords(t, log, "one", "two", "three")
	whole := readBackend(t, backend, testLogPath("a"))
	headerByteCount := storeLogFixedHeaderByteCount + len("approval")
	for _, at := range []int{headerByteCount + storeLogFrameByteCount + 3, len(whole) - 1} {
		damaged := bytes.Clone(whole)
		damaged[at] ^= 0x01
		putBackendFile(t, backend, testLogPath("a"), damaged)
		if _, err := readLogRecords(log); !errors.Is(err, ErrSidecarStoreFailed) {
			t.Errorf("a flip at %d reads %v", at, err)
		}
		relockTestInstance(t, instance)
		if err := log.Append([]byte("more")); !errors.Is(err, ErrSidecarStoreFailed) {
			t.Errorf("an append after a flip at %d answered %v", at, err)
		}
	}
	// a frame whose complement disagrees, with bytes after it, is damage, not a torn write
	damaged := bytes.Clone(whole)
	damaged[headerByteCount] ^= 0x01
	putBackendFile(t, backend, testLogPath("a"), damaged)
	if _, err := readLogRecords(log); !errors.Is(err, ErrSidecarStoreFailed) {
		t.Errorf("a damaged frame reads %v", err)
	}
}

// Record bytes as stored: the header's length, then each frame's span.
func splitTestLog(t *testing.T, whole []byte) ([]byte, [][]byte) {
	t.Helper()
	headerByteCount := storeLogFixedHeaderByteCount + int(whole[13])
	records := [][]byte{}
	for at := headerByteCount; at < len(whole); {
		byteCount := storeLogFrameByteCount + int(binary.BigEndian.Uint32(whole[at:]))
		records = append(records, whole[at:at+byteCount])
		at += byteCount
	}
	return whole[:headerByteCount], records
}

// Two records swapped, or one dropped from the middle, fail.
func TestReorderFails(t *testing.T) {
	backend := NewSidecarMemoryBackend()
	_, log := openTestLog(t, backend, "a")
	appendTestRecords(t, log, "one", "two", "three")
	header, records := splitTestLog(t, readBackend(t, backend, testLogPath("a")))
	reordered := bytes.Join([][]byte{header, records[1], records[0], records[2]}, nil)
	putBackendFile(t, backend, testLogPath("a"), reordered)
	if _, err := readLogRecords(log); !errors.Is(err, ErrSidecarStoreFailed) {
		t.Errorf("reordered reads %v", err)
	}
	dropped := bytes.Join([][]byte{header, records[0], records[2]}, nil)
	putBackendFile(t, backend, testLogPath("a"), dropped)
	if _, err := readLogRecords(log); !errors.Is(err, ErrSidecarStoreFailed) {
		t.Errorf("a middle record dropped reads %v", err)
	}
}

// A log moved to another path, another class or another network fails.
func TestMoveToAnotherPathFails(t *testing.T) {
	backend := NewSidecarMemoryBackend()
	instance, log := openTestLog(t, backend, "a")
	appendTestRecords(t, log, "one")
	content := readBackend(t, backend, testLogPath("a"))

	putBackendFile(t, backend, testLogPath("b"), content)
	moved, err := OpenSidecarStoreLog(storeOf(t, instance, testNetworkId, "approval"), "b")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readLogRecords(moved); !errors.Is(err, ErrSidecarStoreFailed) {
		t.Errorf("moved reads %v", err)
	}

	putBackendFile(t, backend, networkFilePath(testNetworkId, "run/a"), content)
	otherClass, err := OpenSidecarStoreLog(storeOf(t, instance, testNetworkId, "run"), "a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readLogRecords(otherClass); !errors.Is(err, ErrSidecarStoreFailed) {
		t.Errorf("another class reads %v", err)
	}

	enrollTestNetwork(t, instance, otherTestNetworkId)
	putBackendFile(t, backend, networkFilePath(otherTestNetworkId, "approval/a"), content)
	otherNetwork, err := OpenSidecarStoreLog(storeOf(t, instance, otherTestNetworkId, "approval"), "a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readLogRecords(otherNetwork); !errors.Is(err, ErrSidecarStoreFailed) {
		t.Errorf("another network reads %v", err)
	}
}

// A locked keychain appends and reads nothing, and the log reads whole once it opens.
func TestLogLocked(t *testing.T) {
	instance, log := openTestLog(t, NewSidecarMemoryBackend(), "a")
	appendTestRecords(t, log, "one")
	instance.Lock()
	if err := log.Append([]byte("two")); !errors.Is(err, ErrSidecarStoreLocked) {
		t.Errorf("a locked append answered %v", err)
	}
	if _, err := readLogRecords(log); !errors.Is(err, ErrSidecarStoreLocked) {
		t.Errorf("a locked read answered %v", err)
	}
	if err := instance.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	appendTestRecords(t, log, "two")
	requireRecords(t, readTestLog(t, log), "one", "two")
}

// Appends from many goroutines to one path each land once, whole, in some order.
func TestConcurrentAppendsSerialize(t *testing.T) {
	_, log := openTestLog(t, NewSidecarMemoryBackend(), "a")
	var group sync.WaitGroup
	for i := 0; i < 16; i += 1 {
		group.Add(1)
		go func() {
			defer group.Done()
			if err := log.Append([]byte(fmt.Sprintf("record %d", i))); err != nil {
				t.Error(err)
			}
		}()
	}
	group.Wait()
	records := readTestLog(t, log)
	seen := map[string]bool{}
	for _, record := range records {
		seen[string(record)] = true
	}
	if len(records) != 16 || len(seen) != 16 {
		t.Errorf("%d records, %d distinct", len(records), len(seen))
	}
}

// A rotation moves a log to the new root and its chain survives; appends after it chain on.
func TestLogSurvivesRotation(t *testing.T) {
	backend := NewSidecarMemoryBackend()
	instance, log := openTestLog(t, backend, "a")
	appendTestRecords(t, log, "one", "two")
	before := readBackend(t, backend, testLogPath("a"))
	if err := instance.RotateKeychain(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	after := readBackend(t, backend, testLogPath("a"))
	if bytes.Equal(before, after) {
		t.Fatal("the rotation left the log on its old root")
	}
	if binary.BigEndian.Uint64(after[5:13]) == binary.BigEndian.Uint64(before[5:13]) {
		t.Error("the log's header names the old root")
	}
	requireRecords(t, readTestLog(t, log), "one", "two")
	appendTestRecords(t, log, "three")
	requireRecords(t, readTestLog(t, log), "one", "two", "three")
}

// A record past the bound is refused before anything is written.
func TestLogRecordBound(t *testing.T) {
	backend := NewSidecarMemoryBackend()
	_, log := openTestLog(t, backend, "a")
	if err := log.Append(make([]byte, StoreLogRecordMaxByteCount+1)); !errors.Is(err, ErrStoreLogRecordTooLarge) {
		t.Errorf("an oversize record answered %v", err)
	}
	if _, err := backend.Open(testLogPath("a")); !errors.Is(err, ErrSidecarStoreAbsent) {
		t.Errorf("an oversize record left a file: %v", err)
	}
}

// Any bytes at a log's path read without a panic, and a read that answers nil handed over records that fit what was
// there: the decoder is total, and takes no more memory than the file holds plus one record's bound.
func FuzzStoreLogRead(f *testing.F) {
	backend := NewSidecarMemoryBackend()
	settings := cheapKeychainSettings()
	settings.KeychainSettings.AutoLockTimeout = 0
	clock := newTestClock()
	instance, err := newSidecarInstance(context.Background(),
		&SidecarInstanceArgs{Backend: backend, KeyStore: newFakeKeyStore(), Settings: settings},
		clock.now, clock.after, rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	defer instance.Close()
	if err := instance.Unlock(nil); err != nil {
		f.Fatal(err)
	}
	if _, err := instance.createKeychain(testNetworkId); err != nil {
		f.Fatal(err)
	}
	store, err := instance.Store(&testNetworkId).Directory("approval", "approval")
	if err != nil {
		f.Fatal(err)
	}
	log, err := OpenSidecarStoreLog(store, "a")
	if err != nil {
		f.Fatal(err)
	}
	for _, record := range []string{"one", "", "three"} {
		if err := log.Append([]byte(record)); err != nil {
			f.Fatal(err)
		}
	}
	valid, err := readBackendFile(backend, testLogPath("a"), 1024*1024)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add(valid[:len(valid)-3])
	f.Add(append(bytes.Clone(valid), 0, 0, 0))
	f.Add([]byte(storeLogMagic))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, content []byte) {
		putBackendFile(t, backend, testLogPath("a"), content)
		byteCount := 0
		err := log.Read(func(index uint64, record []byte) error {
			byteCount += len(record) + storeLogSealedMinByteCount + storeLogFrameByteCount
			return nil
		})
		if err == nil && len(content) < byteCount {
			t.Errorf("records of %d bytes from a file of %d", byteCount, len(content))
		}
		if err != nil && !errors.Is(err, ErrSidecarStoreFailed) {
			t.Errorf("a read answered %v", err)
		}
	})
}

// A visitor's error ends the read, and Read answers it.
func TestLogReadStopsAtVisitError(t *testing.T) {
	_, log := openTestLog(t, NewSidecarMemoryBackend(), "a")
	appendTestRecords(t, log, "one", "two")
	stop := errors.New("synthetic stop")
	visited := 0
	err := log.Read(func(index uint64, record []byte) error {
		visited += 1
		return stop
	})
	if !errors.Is(err, stop) || visited != 1 {
		t.Errorf("err %v after %d visits", err, visited)
	}
}
