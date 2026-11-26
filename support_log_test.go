//go:build !ios_extension && !sidecar_http

package sidecar

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// A clock the test moves. Its timers never fire, so the writer flushes only when a bundle or Close asks, and every
// test reads exactly what it wrote.
type supportLogTestClock struct {
	stateLock sync.Mutex
	now       time.Time
}

func newSupportLogTestClock() *supportLogTestClock {
	return &supportLogTestClock{now: time.Date(2026, time.November, 24, 12, 0, 0, 0, time.UTC)}
}

func (self *supportLogTestClock) Now() time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.now
}

func (self *supportLogTestClock) After(timeout time.Duration) <-chan time.Time {
	return make(chan time.Time)
}

func (self *supportLogTestClock) AfterFunc(timeout time.Duration, function func()) (stop func() bool) {
	return func() bool { return true }
}

func (self *supportLogTestClock) advance(by time.Duration) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.now = self.now.Add(by)
}

// A ring in a test's directory on clock, closed at the test's end.
func openTestSupportLog(t *testing.T, directory string, settings *SupportSettings, clock Clock) *SupportLog {
	t.Helper()
	if settings == nil {
		settings = DefaultSupportSettings()
	}
	log, err := OpenSupportLog(&SupportLogArgs{Directory: directory, Settings: settings, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(log.Close)
	return log
}

// The bundle's events of one code, by component.code.
func testSupportLogEvents(document *SupportLogBundleDocument, name string) []*SupportLogBundleEvent {
	events := []*SupportLogBundleEvent{}
	for _, event := range document.Events {
		if event.Component+"."+event.Code == name {
			events = append(events, event)
		}
	}
	return events
}

// A bundle of the last day, checked to open as it says.
func testSupportLogBundle(t *testing.T, log *SupportLog, host *SupportLogBundleHost) *SupportLogBundle {
	t.Helper()
	bundle, err := log.Bundle(&SupportLogBundleArgs{Host: host})
	if err != nil {
		t.Fatal(err)
	}
	opened, err := SupportLogBundleOpen(bundle.Bytes, 64*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	if len(opened.Events) != len(bundle.Document.Events) || opened.Header.Events != bundle.Manifest.Events {
		t.Fatalf("the bundle opens to %d events, and says %d", len(opened.Events), bundle.Manifest.Events)
	}
	if int64(len(bundle.Bytes)) != bundle.Manifest.ByteCount {
		t.Fatalf("the manifest says %d bytes of %d", bundle.Manifest.ByteCount, len(bundle.Bytes))
	}
	return bundle
}

func TestSupportLogWritesAnEventABundleRenders(t *testing.T) {
	clock := newSupportLogTestClock()
	log := openTestSupportLog(t, t.TempDir(), nil, clock)
	log.Event(SupportLogCodeDaemonStarted, SupportLogFieldRelease("2026.11.24+1234"), SupportLogFieldAutoSpawned(true))
	clock.advance(90 * time.Minute)
	log.Event(SupportLogCodeDaemonStopped, SupportLogFieldStopReason(SupportLogStopReasonIdle), SupportLogFieldUptime(90*time.Minute))
	bundle := testSupportLogBundle(t, log, &SupportLogBundleHost{Version: "2026.11.24+1234", Channel: "stable"})

	started := testSupportLogEvents(bundle.Document, "daemon.started")
	if len(started) != 1 || started[0].Severity != "info" || started[0].Fields["release"] != "2026.11.24+1234" || started[0].Fields["auto_spawned"] != true {
		t.Fatalf("daemon.started reads %+v", started)
	}
	stopped := testSupportLogEvents(bundle.Document, "daemon.stopped")
	if len(stopped) != 1 || stopped[0].Fields["stop_reason"] != "idle" || stopped[0].Fields["uptime"] != "1-23h" {
		t.Fatalf("daemon.stopped reads %+v", stopped)
	}
	if stopped[0].T-started[0].T != int64((90 * time.Minute).Seconds()) {
		t.Fatalf("the events are %d s apart", stopped[0].T-started[0].T)
	}
	header := bundle.Document.Header
	if header.Version != "2026.11.24+1234" || header.Channel != "stable" || header.Registry != SupportLogRegistryVersion || header.Os == "" || header.Arch == "" {
		t.Fatalf("the header reads %+v", header)
	}
	if header.First != started[0].T || header.Last != stopped[0].T {
		t.Fatalf("the header's window is %d to %d", header.First, header.Last)
	}
	codes := map[string]int{}
	for _, count := range bundle.Manifest.Codes {
		codes[count.Component+"."+count.Code] = count.Count
	}
	if codes["daemon.started"] != 1 || codes["daemon.stopped"] != 1 || codes["support_log.opened"] != 1 {
		t.Fatalf("the manifest counts %v", codes)
	}
}

func TestSupportLogKeepsCountsDurationsAndSizesAsBuckets(t *testing.T) {
	log := openTestSupportLog(t, t.TempDir(), nil, newSupportLogTestClock())
	cases := []struct {
		count     int64
		countWant string
		size      int64
		sizeWant  string
		waited    time.Duration
		waitWant  string
	}{
		{count: -3, countWant: "0", size: 0, sizeWant: "0", waited: -time.Second, waitWant: "<10ms"},
		{count: 1, countWant: "1", size: 1023, sizeWant: "<1KiB", waited: 9 * time.Millisecond, waitWant: "<10ms"},
		{count: 9, countWant: "2-9", size: 1024, sizeWant: "1-63KiB", waited: 10 * time.Millisecond, waitWant: "10-99ms"},
		{count: 10, countWant: "10-99", size: 5 * 1024 * 1024, sizeWant: "1-15MiB", waited: 3 * time.Minute, waitWant: "1-9m"},
		{count: 123456789, countWant: "100+", size: 1 << 40, sizeWant: "256MiB+", waited: 400 * time.Hour, waitWant: "1d+"},
	}
	for _, c := range cases {
		log.Event(SupportLogCodeSupportMessageGivenUp, SupportLogFieldAttempts(c.count), SupportLogFieldWaited(c.waited))
		log.Event(SupportLogCodeSupportMessageQueued, SupportLogFieldBodyBytes(c.size))
	}
	bundle := testSupportLogBundle(t, log, nil)
	givenUp := testSupportLogEvents(bundle.Document, "support.message_given_up")
	queued := testSupportLogEvents(bundle.Document, "support.message_queued")
	if len(givenUp) != len(cases) || len(queued) != len(cases) {
		t.Fatalf("%d and %d events of %d", len(givenUp), len(queued), len(cases))
	}
	for i, c := range cases {
		if givenUp[i].Fields["attempts"] != c.countWant || givenUp[i].Fields["waited"] != c.waitWant || queued[i].Fields["body_bytes"] != c.sizeWant {
			t.Errorf("case %d reads %v and %v", i, givenUp[i].Fields, queued[i].Fields)
		}
	}
}

func TestSupportLogRefusesAndCountsFieldsTheCodeDoesNotDeclare(t *testing.T) {
	log := openTestSupportLog(t, t.TempDir(), nil, newSupportLogTestClock())
	// a field another code declares, the zero field, a second field of one number and an enum value its enum lacks
	log.Event(SupportLogCodeDaemonStarted,
		SupportLogFieldRelease("1.2.3"), SupportLogFieldRun([]byte("run")), SupportLogField{}, SupportLogFieldRelease("4.5.6"))
	log.Event(SupportLogCodeDaemonStopped, SupportLogFieldStopReason(SupportLogStopReason(99)))
	// a code the registry does not hold
	log.Event(SupportLogCode(9999), SupportLogFieldCount(1))
	bundle := testSupportLogBundle(t, log, nil)
	started := testSupportLogEvents(bundle.Document, "daemon.started")
	if len(started) != 1 || len(started[0].Fields) != 1 || started[0].Fields["release"] != "1.2.3" {
		t.Fatalf("daemon.started reads %+v", started)
	}
	stopped := testSupportLogEvents(bundle.Document, "daemon.stopped")
	if len(stopped) != 1 || len(stopped[0].Fields) != 0 {
		t.Fatalf("daemon.stopped reads %+v", stopped)
	}
	refused := testSupportLogEvents(bundle.Document, "support_log.field_refused")
	if len(refused) != 1 || refused[0].Fields["count"] != "2-9" {
		t.Fatalf("field_refused reads %+v", refused)
	}
}

func TestSupportLogHoldsAVersionThatFailsItsCheckAsInvalid(t *testing.T) {
	log := openTestSupportLog(t, t.TempDir(), nil, newSupportLogTestClock())
	for _, version := range []string{"", "2.1.3", "v0.45.0", "2026.11.24-a1b2c3d", "hunter2", "1.0-hunter2", "1.2.3 rm -rf", "/Users/someone", "12345678901234567890.1.2.3.4.5"} {
		log.Event(SupportLogCodeAppStarted, SupportLogFieldRelease(version))
	}
	bundle := testSupportLogBundle(t, log, &SupportLogBundleHost{Version: "hunter2", Channel: "Stable", HarnessVersion: "2.1.3"})
	got := []any{}
	for _, event := range testSupportLogEvents(bundle.Document, "app.started") {
		got = append(got, event.Fields["release"])
	}
	want := []any{"", "2.1.3", "v0.45.0", "2026.11.24-a1b2c3d", "invalid", "invalid", "invalid", "invalid", "invalid"}
	if !slices.Equal(got, want) {
		t.Fatalf("versions read %v", got)
	}
	header := bundle.Document.Header
	if header.Version != "invalid" || header.Channel != "other" || header.HarnessVersion != "2.1.3" || header.GatewayVersion != "" {
		t.Fatalf("the header reads %+v", header)
	}
}

func TestSupportLogTokensRelateWithinABundleAndNeverAcross(t *testing.T) {
	directory := t.TempDir()
	log := openTestSupportLog(t, directory, nil, newSupportLogTestClock())
	run := []byte("0123456789abcdef")
	other := []byte("fedcba9876543210")
	log.Event(SupportLogCodeSupportMessageRefused, SupportLogFieldRun(run), SupportLogFieldAgent(run))
	log.Event(SupportLogCodeSupportMessageRefused, SupportLogFieldRun(run))
	log.Event(SupportLogCodeSupportMessageRefused, SupportLogFieldRun(other))
	log.Event(SupportLogCodeSupportMessageRefused, SupportLogFieldRun(nil))
	first := testSupportLogEvents(testSupportLogBundle(t, log, nil).Document, "support.message_refused")
	second := testSupportLogEvents(testSupportLogBundle(t, log, nil).Document, "support.message_refused")
	if len(first) != 4 || len(second) != 4 {
		t.Fatalf("%d and %d events", len(first), len(second))
	}
	token := func(event *SupportLogBundleEvent, name string) string {
		text, _ := event.Fields[name].(string)
		return text
	}
	if token(first[0], "run") == "" || token(first[0], "run") != token(first[1], "run") {
		t.Fatalf("one run's tokens differ within a bundle: %v", first[:2])
	}
	if token(first[0], "run") == token(first[2], "run") || token(first[0], "run") == token(first[0], "agent") {
		t.Fatal("two runs, or a run and an agent of equal ids, share a token")
	}
	if len(token(first[0], "run")) != 2*DefaultSupportSettings().BundleTokenByteCount {
		t.Fatalf("a token of %d hex digits", len(token(first[0], "run")))
	}
	if token(first[3], "run") != "" {
		t.Fatalf("an empty id reads %q", token(first[3], "run"))
	}
	if token(first[0], "run") == token(second[0], "run") {
		t.Fatal("two bundles share a token")
	}
	// the ring holds neither the id nor its hex
	for _, data := range testSupportLogRingFiles(t, directory) {
		if bytes.Contains(data, run) || bytes.Contains(data, []byte(hex.EncodeToString(run))) {
			t.Fatal("the ring holds a token's id")
		}
	}
}

// Each segment file of a ring, by name.
func testSupportLogRingFiles(t *testing.T, directory string) map[string][]byte {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		files[entry.Name()] = data
	}
	return files
}

func TestSupportLogPrunesTheOldestSegmentsPastItsSize(t *testing.T) {
	settings := DefaultSupportSettings()
	settings.RingMaxByteCount = 4 * 1024
	settings.SegmentMaxByteCount = 1024
	directory := t.TempDir()
	clock := newSupportLogTestClock()
	log := openTestSupportLog(t, directory, settings, clock)
	for i := range 400 {
		log.Event(SupportLogCodeSupportPostFailed, SupportLogFieldPostResult(SupportLogPostResultTimeout), SupportLogFieldAttempts(int64(i)))
		if i%20 == 0 {
			clock.advance(time.Second)
			log.flush()
		}
	}
	bundle := testSupportLogBundle(t, log, nil)
	total := int64(0)
	for name, data := range testSupportLogRingFiles(t, directory) {
		if strings.HasSuffix(name, ".seg") {
			total += int64(len(data))
		}
	}
	if settings.RingMaxByteCount+settings.SegmentMaxByteCount < total {
		t.Fatalf("the ring holds %d bytes", total)
	}
	if len(testSupportLogEvents(bundle.Document, "support_log.segment_pruned")) == 0 {
		t.Fatal("no segment_pruned event")
	}
	posted := testSupportLogEvents(bundle.Document, "support.post_failed")
	if len(posted) == 0 || 400 <= len(posted) {
		t.Fatalf("%d events kept of 400", len(posted))
	}
}

func TestSupportLogDropsEventsPastItsAge(t *testing.T) {
	directory := t.TempDir()
	clock := newSupportLogTestClock()
	log := openTestSupportLog(t, directory, nil, clock)
	log.Event(SupportLogCodeAppStarted, SupportLogFieldRelease("1.0"))
	log.flush()
	clock.advance(2 * 24 * time.Hour)
	log.Event(SupportLogCodeAppStarted, SupportLogFieldRelease("2.0"))
	log.flush()
	clock.advance(6 * 24 * time.Hour)
	log.Event(SupportLogCodeAppStarted, SupportLogFieldRelease("3.0"))
	bundle, err := log.Bundle(&SupportLogBundleArgs{Since: clock.Now().Add(-30 * 24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	got := []any{}
	for _, event := range testSupportLogEvents(bundle.Document, "app.started") {
		got = append(got, event.Fields["release"])
	}
	// 1.0 is 8 days old, past the ring's 7, so no bundle reads it; 2.0's stays, inside the window
	if !slices.Equal(got, []any{"2.0", "3.0"}) {
		t.Fatalf("the bundle holds %v", got)
	}
	segmentCount := func() int {
		count := 0
		for name := range testSupportLogRingFiles(t, directory) {
			if strings.HasSuffix(name, ".seg") {
				count += 1
			}
		}
		return count
	}
	if segmentCount() != 3 {
		t.Fatalf("%d segments while the oldest's successor is inside the age", segmentCount())
	}
	// once 2.0's segment began 7 days ago, every event of the first is older, and it goes
	clock.advance(24 * time.Hour)
	log.Event(SupportLogCodeAppStarted, SupportLogFieldRelease("4.0"))
	log.flush()
	if segmentCount() != 3 {
		t.Fatalf("%d segments after the oldest passed its age", segmentCount())
	}
	if pruned := testSupportLogEvents(testSupportLogBundle(t, log, nil).Document, "support_log.segment_pruned"); len(pruned) != 1 || pruned[0].Fields["prune_reason"] != "age" {
		t.Fatalf("segment_pruned reads %+v", pruned)
	}
}

func TestSupportLogBundleTakesItsWindow(t *testing.T) {
	clock := newSupportLogTestClock()
	log := openTestSupportLog(t, t.TempDir(), nil, clock)
	log.Event(SupportLogCodeAppStarted, SupportLogFieldRelease("1.0"))
	clock.advance(30 * time.Hour)
	since := clock.Now()
	log.Event(SupportLogCodeAppStarted, SupportLogFieldRelease("2.0"))
	clock.advance(time.Hour)
	log.Event(SupportLogCodeAppStarted, SupportLogFieldRelease("3.0"))
	read := func(args *SupportLogBundleArgs) []any {
		bundle, err := log.Bundle(args)
		if err != nil {
			t.Fatal(err)
		}
		got := []any{}
		for _, event := range testSupportLogEvents(bundle.Document, "app.started") {
			got = append(got, event.Fields["release"])
		}
		return got
	}
	if got := read(&SupportLogBundleArgs{}); !slices.Equal(got, []any{"2.0", "3.0"}) {
		t.Fatalf("the last day holds %v", got)
	}
	if got := read(&SupportLogBundleArgs{Since: since.Add(time.Second)}); !slices.Equal(got, []any{"3.0"}) {
		t.Fatalf("since the item began holds %v", got)
	}
	if got := read(&SupportLogBundleArgs{Since: since.Add(-100 * 24 * time.Hour)}); !slices.Equal(got, []any{"1.0", "2.0", "3.0"}) {
		t.Fatalf("the longest window holds %v", got)
	}
}

func TestSupportLogBundleLeavesOutTheOldestPastItsBound(t *testing.T) {
	settings := DefaultSupportSettings()
	settings.BundleMaxByteCount = 2 * 1024
	clock := newSupportLogTestClock()
	log := openTestSupportLog(t, t.TempDir(), settings, clock)
	for i := range 2000 {
		log.Event(SupportLogCodeSupportMessageRefused, SupportLogFieldRefusal(SupportLogRefusal(1+i%12)), SupportLogFieldRun([]byte{byte(i), byte(i >> 8)}))
		if i%100 == 0 {
			clock.advance(time.Second)
		}
	}
	bundle := testSupportLogBundle(t, log, nil)
	if settings.BundleMaxByteCount < int64(len(bundle.Bytes)) {
		t.Fatalf("a bundle of %d bytes", len(bundle.Bytes))
	}
	header := bundle.Document.Header
	if header.Omitted == 0 || header.Events == 0 {
		t.Fatalf("the header reads %+v", header)
	}
	last := bundle.Document.Events[len(bundle.Document.Events)-1]
	if last.T != clock.Now().Unix() {
		t.Fatal("the newest event was left out")
	}
}

func TestSupportLogDropsAndCountsPastItsHeldBound(t *testing.T) {
	settings := DefaultSupportSettings()
	settings.PendingMaxByteCount = 256
	log := openTestSupportLog(t, t.TempDir(), settings, newSupportLogTestClock())
	// the writer's timer never fires here, and a wake only flushes what is held, so some are dropped
	log.stateLock.Lock()
	for range 100 {
		record, _ := log.encodeEvent(0, SupportLogCodeAppStarted, []SupportLogField{SupportLogFieldRelease("1.0")})
		if settings.PendingMaxByteCount < len(log.pending)+len(record) {
			log.droppedCount += 1
			continue
		}
		log.pending = append(log.pending, record...)
	}
	log.stateLock.Unlock()
	bundle := testSupportLogBundle(t, log, nil)
	dropped := testSupportLogEvents(bundle.Document, "support_log.events_dropped")
	if len(dropped) != 1 || dropped[0].Fields["count"] != "10-99" {
		t.Fatalf("events_dropped reads %+v", dropped)
	}
}

func TestSupportLogEventNeverWaitsAndDropsPastItsBound(t *testing.T) {
	settings := DefaultSupportSettings()
	settings.PendingMaxByteCount = 128
	log := openTestSupportLog(t, t.TempDir(), settings, newSupportLogTestClock())
	// hold the writer off the ring, so held events can only grow
	log.fileLock.Lock()
	for range 50 {
		log.Event(SupportLogCodeAppStarted, SupportLogFieldRelease("1.0"))
	}
	droppedCount := func() int64 {
		log.stateLock.Lock()
		defer log.stateLock.Unlock()
		return log.droppedCount
	}()
	log.fileLock.Unlock()
	if droppedCount == 0 {
		t.Fatal("nothing was dropped past the held bound")
	}
}

func TestSupportLogReadsUpToATornRecordAndSaysSo(t *testing.T) {
	directory := t.TempDir()
	clock := newSupportLogTestClock()
	log := openTestSupportLog(t, directory, nil, clock)
	log.Event(SupportLogCodeAppStarted, SupportLogFieldRelease("1.0"))
	log.Event(SupportLogCodeAppStarted, SupportLogFieldRelease("2.0"))
	log.Close()
	// a crash mid-write: the last record's checksum is cut off
	segments := []string{}
	for name := range testSupportLogRingFiles(t, directory) {
		if strings.HasSuffix(name, ".seg") {
			segments = append(segments, name)
		}
	}
	slices.Sort(segments)
	path := filepath.Join(directory, segments[len(segments)-1])
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data[:len(data)-2], 0o600); err != nil {
		t.Fatal(err)
	}
	clock.advance(time.Second)
	reopened := openTestSupportLog(t, directory, nil, clock)
	bundle := testSupportLogBundle(t, reopened, nil)
	got := []any{}
	for _, event := range testSupportLogEvents(bundle.Document, "app.started") {
		got = append(got, event.Fields["release"])
	}
	if !slices.Equal(got, []any{"1.0"}) {
		t.Fatalf("the torn ring reads %v", got)
	}
	unreadable := testSupportLogEvents(testSupportLogBundle(t, reopened, nil).Document, "support_log.segment_unreadable")
	if len(unreadable) != 1 || unreadable[0].Fields["unreadable_reason"] != "truncated" {
		t.Fatalf("segment_unreadable reads %+v", unreadable)
	}
}

func TestSupportLogKeepsItsEventsAndKeyAcrossAReopen(t *testing.T) {
	directory := t.TempDir()
	clock := newSupportLogTestClock()
	log := openTestSupportLog(t, directory, nil, clock)
	log.Event(SupportLogCodeSupportEventReceived, SupportLogFieldEntry([]byte("100171")))
	log.Close()
	reopened := openTestSupportLog(t, directory, nil, clock)
	reopened.Event(SupportLogCodeSupportEventReceived, SupportLogFieldEntry([]byte("100171")))
	received := testSupportLogEvents(testSupportLogBundle(t, reopened, nil).Document, "support.event_received")
	if len(received) != 2 || received[0].Fields["entry"] != received[1].Fields["entry"] {
		t.Fatalf("one entry across a reopen reads %+v", received)
	}
	if opened := testSupportLogEvents(testSupportLogBundle(t, reopened, nil).Document, "support_log.opened"); len(opened) != 2 {
		t.Fatalf("%d opened events", len(opened))
	}
}

func TestSupportLogNilAndClosedWriteNothing(t *testing.T) {
	var log *SupportLog
	log.Event(SupportLogCodeAppStarted, SupportLogFieldRelease("1.0"))
	log.Close()
	if _, err := log.Bundle(nil); err == nil {
		t.Fatal("a nil log built a bundle")
	}
	SupportLogOrNone(nil).Event(SupportLogCodeAppStarted, SupportLogFieldRelease("1.0"))

	directory := t.TempDir()
	open := openTestSupportLog(t, directory, nil, newSupportLogTestClock())
	open.Close()
	open.Event(SupportLogCodeAppStarted, SupportLogFieldRelease("9.9"))
	open.Close()
	reopened := openTestSupportLog(t, directory, nil, newSupportLogTestClock())
	if got := testSupportLogEvents(testSupportLogBundle(t, reopened, nil).Document, "app.started"); len(got) != 0 {
		t.Fatalf("a closed log wrote %+v", got)
	}
}

func TestSupportLogEventIsSafeForConcurrentUse(t *testing.T) {
	log := openTestSupportLog(t, t.TempDir(), nil, newSupportLogTestClock())
	group := sync.WaitGroup{}
	for range 8 {
		group.Go(func() {
			for range 100 {
				log.Event(SupportLogCodeAppStarted, SupportLogFieldRelease("1.0"))
			}
		})
		group.Go(func() {
			if _, err := log.Bundle(nil); err != nil {
				t.Error(err)
			}
		})
	}
	group.Wait()
	if got := testSupportLogEvents(testSupportLogBundle(t, log, nil).Document, "app.started"); len(got) != 800 {
		t.Fatalf("%d events of 800", len(got))
	}
}

func TestSupportLogCodesNameTheirRegistryRows(t *testing.T) {
	codes := SupportLogCodes()
	if len(codes) == 0 || !slices.IsSorted(codes) {
		t.Fatalf("codes %v", codes)
	}
	if SupportLogCodeDaemonStarted.String() != "daemon.started" || SupportLogCode(9999).String() != "" {
		t.Fatal("a code's name")
	}
	if !SupportLogCodeDaemonStarted.Declares("release") || SupportLogCodeDaemonStarted.Declares("run") {
		t.Fatal("a code's fields")
	}
	for _, code := range codes {
		row := supportLogRegistry.codes[code]
		if _, ok := supportLogRegistry.components[row.component]; !ok || supportLogSeverityNames[row.severity] == "" {
			t.Errorf("code %d's row %+v", code, row)
		}
		for _, number := range row.fields {
			if supportLogRegistry.fields[number] == nil {
				t.Errorf("code %s names field %d", code, number)
			}
		}
	}
}

// A deferred ring creates nothing on disk until Start: not its directory, its key or a segment, whatever Event takes
// and a bundle reads meanwhile; Start writes what it held with the times it was held at, and a second Start does
// nothing more. One closed before Start writes nothing at all, and one opened over a ring reads its key, so its tokens
// relate to the ring's earlier ones, and writes none of it again.
func TestSupportLogDeferredWritesNothingUntilStart(t *testing.T) {
	clock := newSupportLogTestClock()
	directory := filepath.Join(t.TempDir(), "support-log")
	open := func() *SupportLog {
		log, err := OpenSupportLog(&SupportLogArgs{Directory: directory, Settings: DefaultSupportSettings(), Clock: clock, Deferred: true})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(log.Close)
		return log
	}
	log := open()
	held := clock.Now()
	log.Event(SupportLogCodeAppStarted, SupportLogFieldRelease("2026.11.24-1"))
	log.flush()
	if bundle, err := log.Bundle(nil); err != nil || bundle.Document.Header.Events != 0 {
		t.Fatalf("a bundle before Start: %+v, %v", bundle, err)
	}
	if _, err := os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a deferred ring made its directory: %v", err)
	}
	clock.advance(time.Minute)
	if err := log.Start(); err != nil {
		t.Fatal(err)
	}
	if err := log.Start(); err != nil {
		t.Fatal(err)
	}
	bundle, err := log.Bundle(nil)
	if err != nil {
		t.Fatal(err)
	}
	codes := map[string]int64{}
	for _, event := range bundle.Document.Events {
		codes[event.Component+"."+event.Code] = event.T
	}
	if codes["app.started"] != held.Unix() || codes["support_log.opened"] != clock.Now().Unix() {
		t.Fatalf("after Start the ring holds %v", codes)
	}
	key, err := os.ReadFile(filepath.Join(directory, supportLogKeyFileName))
	if err != nil {
		t.Fatal(err)
	}
	log.Close()

	// over the ring: its key read, nothing written before Start, nothing at all when closed first
	before := map[string][]byte{}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		before[entry.Name()] = data
	}
	again := open()
	if !bytes.Equal(again.key, key) {
		t.Fatal("a deferred ring over a ring drew a new key")
	}
	again.Event(SupportLogCodeAppStopped, SupportLogFieldUptime(time.Hour))
	again.Close()
	entries, err = os.ReadDir(directory)
	if err != nil || len(entries) != len(before) {
		t.Fatalf("%d files after a closed deferred ring, %d before: %v", len(entries), len(before), err)
	}
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil || !bytes.Equal(data, before[entry.Name()]) {
			t.Fatalf("a deferred ring closed before Start changed %s", entry.Name())
		}
	}
	if err := again.Start(); err == nil {
		t.Fatal("a closed ring started")
	}
}
