//go:build sidecar_testhooks && !sidecar_http && !js && !ios && !android && !sdk_mobile_bind && !windows

// FS-73's twin (§22.8's twins; EVS2-M10-29): the git-lfs tip check switched off on the pushing device, as a build
// without it would run (sidecar.EvsTestSwitchOffLfsTipCheck), lets the pruned clause's force push to pruned history
// through, and the clause must catch that. The clause runs on a recorder in place of the test, so what it catches
// is the twin's evidence rather than a failure of the test; anything the world itself fails on still fails the test.
// Only the sidecar_testhooks build has the switch, which no release leg is (§22.4).

package evsgit

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar"
)

// The pruned clause with the pushing device's tip check off: see the file header. It fails unless the clause failed
// at the force push that went through.
func Fs73TipCheckOffTwin(t testing.TB, world *World) {
	t.Helper()
	recorder := &fs73Recorder{TB: t}
	done := make(chan struct{})
	go func() {
		defer close(done)
		fs73PrunedHistory(recorder, world, func(device *Device) {
			sidecar.EvsTestSwitchOffLfsTipCheck(device.Mount, true)
			t.Cleanup(func() { sidecar.EvsTestSwitchOffLfsTipCheck(device.Mount, false) })
		})
	}()
	<-done
	failures := recorder.Failures()
	if len(failures) == 0 {
		t.Fatal("with the tip check off the pruned clause passed: it does not catch a force push to pruned history")
	}
	if !strings.Contains(failures[0], "the force push to pruned history went through") {
		t.Fatalf("with the tip check off the pruned clause failed elsewhere: %s", failures[0])
	}
	t.Logf("the twin, the tip check off, is caught: %s", failures[0])
}

// A test the twin's clause runs on: what it fails with is recorded, and a fatal ends the clause's goroutine, as it
// would end a test's.
type fs73Recorder struct {
	testing.TB

	stateLock sync.Mutex
	failures  []string
}

func (self *fs73Recorder) Helper() {}

func (self *fs73Recorder) record(text string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.failures = append(self.failures, text)
}

func (self *fs73Recorder) Failures() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]string{}, self.failures...)
}

func (self *fs73Recorder) Errorf(format string, args ...any) {
	self.record(fmt.Sprintf(format, args...))
}

func (self *fs73Recorder) Error(args ...any) {
	self.record(fmt.Sprint(args...))
}

func (self *fs73Recorder) Fatalf(format string, args ...any) {
	self.record(fmt.Sprintf(format, args...))
	runtime.Goexit()
}

func (self *fs73Recorder) Fatal(args ...any) {
	self.record(fmt.Sprint(args...))
	runtime.Goexit()
}

func (self *fs73Recorder) FailNow() {
	self.record("FailNow")
	runtime.Goexit()
}

func (self *fs73Recorder) Failed() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return 0 < len(self.failures)
}
