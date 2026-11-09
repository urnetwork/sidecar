package dnsservice

import (
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func snapshotFileTestView(t *testing.T, serial uint64) *ZoneView {
	t.Helper()
	return newTestView(t, serial, signingTestRows()...)
}

// A saved view reads back as the same rows at its serial, with its window and interfaces.
func TestSnapshotFileSavesAndLoadsWhole(t *testing.T) {
	directory := t.TempDir()
	file, err := NewSnapshotFile(directory, testRoot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Load(answerTestSettings(t)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("an empty directory loads %v", err)
	}
	signing := newTestSigning(t, testRoot)
	view := snapshotFileTestView(t, 42)
	interfaces := []DnsLbInterface{{Name: "lb-1", Ipv4: netip.MustParseAddr("192.0.2.1"), Router: true}}
	if err := file.Save(view, 7, signing.window, interfaces); err != nil {
		t.Fatal(err)
	}
	saved, err := file.Load(answerTestSettings(t))
	if err != nil {
		t.Fatal(err)
	}
	if saved.View.Serial() != 42 || saved.RestoreSerial != 7 || !reflect.DeepEqual(saved.Interfaces, interfaces) {
		t.Errorf("saved %+v", saved)
	}
	if !dnsKeyWindowsEqual(saved.KeyWindow, signing.window) {
		t.Errorf("window %+v", saved.KeyWindow)
	}
	if diff := RrsetDiff(view, saved.View); len(diff.Rrsets) != 0 {
		t.Errorf("rows differ %v", diff.Rrsets)
	}
	info, err := os.Stat(filepath.Join(directory, dnsSnapshotFileName))
	if err != nil || info.Mode().Perm() != dnsSnapshotFileMode {
		t.Errorf("mode %v %v", info, err)
	}
}

// What a crash leaves, a temporary file beside the last whole one, is removed at open, and the whole
// one still reads.
func TestSnapshotFileRemovesAWriteACrashLeft(t *testing.T) {
	directory := t.TempDir()
	file, err := NewSnapshotFile(directory, testRoot)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Save(snapshotFileTestView(t, 5), 0, nil, nil); err != nil {
		t.Fatal(err)
	}
	torn := filepath.Join(directory, dnsSnapshotFileName+dnsSnapshotTemporarySuffix)
	if err := os.WriteFile(torn, []byte(`{"format":1,"root":"zone.example.","serial":6}`+"\n{"), 0o600); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewSnapshotFile(directory, testRoot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(torn); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the torn write stayed: %v", err)
	}
	saved, err := reopened.Load(answerTestSettings(t))
	if err != nil || saved.View.Serial() != 5 {
		t.Errorf("saved %+v %v", saved, err)
	}
}

// A file that does not read whole is refused, never half-served: cut short, with a line past its end,
// with a row the root's rules refuse, of another root, or of a format this release does not read.
func TestSnapshotFileRefusesAFileThatDoesNotReadWhole(t *testing.T) {
	directory := t.TempDir()
	file, err := NewSnapshotFile(directory, testRoot)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Save(snapshotFileTestView(t, 5), 0, nil, nil); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, dnsSnapshotFileName)
	whole, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.SplitAfter(string(whole), "\n")
	cases := map[string]string{
		"cut short":         strings.Join(lines[:len(lines)-2], ""),
		"a line past":       string(whole) + `{"owner":"x.zone.example.","type":16}` + "\n",
		"a refused row":     strings.Replace(string(whole), `"owner":"www.net1.zone.example."`, `"owner":"www.other.example."`, 1),
		"another root":      strings.Replace(string(whole), `"root":"zone.example."`, `"root":"other.example."`, 1),
		"a format too new":  strings.Replace(string(whole), `"format":1`, `"format":2`, 1),
		"nothing":           "",
		"not json":          "garbage\n",
		"a count that lies": strings.Replace(string(whole), `"row_count":`, `"row_count":1`, 1),
	}
	for name, text := range cases {
		if text == string(whole) {
			t.Fatalf("%s changed nothing", name)
		}
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		if saved, err := file.Load(answerTestSettings(t)); err == nil || errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s: loaded %+v %v", name, saved, err)
		}
	}
	if err := file.Discard(); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Load(answerTestSettings(t)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("after Discard %v", err)
	}
}

// A replaced snapshot is kept with its diff and reload time, listed oldest first, and removed on
// demand; one whose first line does not read is removed, since its diff cannot be posted.
func TestSnapshotFileKeepsReplacedSnapshotsForTheirDiffs(t *testing.T) {
	directory := t.TempDir()
	file, err := NewSnapshotFile(directory, testRoot)
	if err != nil {
		t.Fatal(err)
	}
	older := snapshotFileTestView(t, 5)
	newer := newTestView(t, 5+DnsRestoreSerialJump, testApexRows()...)
	first, err := file.KeepReplaced(older, RrsetDiff(older, newer), testSigningNow)
	if err != nil {
		t.Fatal(err)
	}
	second, err := file.KeepReplaced(snapshotFileTestView(t, 3), RrsetDiff(snapshotFileTestView(t, 3), newer), testSigningNow.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, dnsReplacedFilePrefix+"9-10"+dnsSnapshotFileSuffix), []byte("garbage\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	replaced, err := file.Replaced()
	if err != nil {
		t.Fatal(err)
	}
	if len(replaced) != 2 || replaced[0].path != second.path || replaced[1].path != first.path {
		t.Fatalf("replaced %+v", replaced)
	}
	if replaced[1].Diff.ReplacedSerial != 5 || replaced[1].Diff.Serial != 5+DnsRestoreSerialJump || !replaced[1].ReloadTime.Equal(testSigningNow) {
		t.Errorf("first %+v", replaced[1].Diff)
	}
	if !slices.ContainsFunc(replaced[1].Diff.Rrsets, func(key DnsRecordKey) bool {
		return key == DnsRecordKey{Owner: "www.net1." + testRoot, Type: dns.TypeA}
	}) {
		t.Errorf("rrsets %v", replaced[1].Diff.Rrsets)
	}
	if err := file.DeleteReplaced(first); err != nil {
		t.Fatal(err)
	}
	replaced, err = file.Replaced()
	if err != nil || len(replaced) != 1 || replaced[0].path != second.path {
		t.Errorf("after a delete %+v %v", replaced, err)
	}
	if _, err := file.Load(answerTestSettings(t)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a replaced snapshot read as the current one: %v", err)
	}
}

// A clock whose waits a test fires: After hands back a channel the test closes.
type firingClock struct {
	testClock
	fires chan chan time.Time
}

func (self *firingClock) After(timeout time.Duration) <-chan time.Time {
	fire := make(chan time.Time, 1)
	self.fires <- fire
	return fire
}

// The writer writes a burst of changes once, after its interval, and never writes over a newer view
// what an older one held.
func TestSnapshotWriterCoalescesAndNeverRegresses(t *testing.T) {
	file, err := NewSnapshotFile(t.TempDir(), testRoot)
	if err != nil {
		t.Fatal(err)
	}
	clock := &firingClock{testClock: testClock{now: testSigningNow}, fires: make(chan chan time.Time, 8)}
	writer := newDnsSnapshotWriter(file, clock, time.Second, newDnsMetrics(&declaredMetrics{}))
	done := make(chan struct{})
	go func() {
		defer close(done)
		writer.run(t.Context())
	}()
	writer.set(&dnsSavedState{view: snapshotFileTestView(t, 1)})
	fire := <-clock.fires
	writer.set(&dnsSavedState{view: snapshotFileTestView(t, 2)})
	writer.set(&dnsSavedState{view: snapshotFileTestView(t, 3)})
	fire <- testSigningNow
	for {
		serial, changed := writer.writtenSerial.Get()
		if serial == 3 {
			break
		}
		select {
		case <-changed:
		case <-t.Context().Done():
			t.Fatalf("written %d", serial)
		}
	}
	// a write of serial 4 lands now; an older generation then never overwrites it
	writer.saveNow(&dnsSavedState{view: snapshotFileTestView(t, 4)})
	writer.save(&dnsSavedState{view: snapshotFileTestView(t, 2)}, 1)
	saved, err := file.Load(answerTestSettings(t))
	if err != nil || saved.View.Serial() != 4 {
		t.Errorf("saved %+v %v", saved, err)
	}
}
