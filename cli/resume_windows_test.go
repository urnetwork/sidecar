//go:build windows

// powrprof's resume (resume_windows.go): the callback calls the watch its context names at both resume events, and
// nothing at a suspend, at another event, or for a context no watch holds.

package main

import (
	"sync/atomic"
	"testing"
	"unsafe"
)

// The callback's dispatch, called as powrprof would call it.
func TestWindowsResumeCallbackCallsItsWatchAtAResume(t *testing.T) {
	urWindowsResume.once.Do(func() {
		urWindowsResume.watches = map[uintptr]*urWindowsResumeWatchEntry{}
	})
	resumes := &atomic.Int64{}
	watch := &urWindowsResumeWatchEntry{token: new(byte), resumed: func() { resumes.Add(1) }}
	key := uintptr(unsafe.Pointer(watch.token))
	urWindowsResume.stateLock.Lock()
	urWindowsResume.watches[key] = watch
	urWindowsResume.stateLock.Unlock()
	t.Cleanup(func() {
		urWindowsResume.stateLock.Lock()
		defer urWindowsResume.stateLock.Unlock()
		delete(urWindowsResume.watches, key)
	})
	// PBT_APMSUSPEND and PBT_POWERSETTINGCHANGE are no resume
	for _, eventType := range []uint32{0x0004, 0x8013} {
		urWindowsResumeCallback(key, eventType, 0)
	}
	if resumes.Load() != 0 {
		t.Fatalf("%d resumes from events that are none", resumes.Load())
	}
	urWindowsResumeCallback(key, urWindowsPbtApmResumeAutomatic, 0)
	urWindowsResumeCallback(key, urWindowsPbtApmResumeSuspend, 0)
	if resumes.Load() != 2 {
		t.Fatalf("%d resumes from both resume events", resumes.Load())
	}
	urWindowsResumeCallback(0, urWindowsPbtApmResumeAutomatic, 0)
	if resumes.Load() != 2 {
		t.Fatal("a context no watch holds reached a watch")
	}
}
