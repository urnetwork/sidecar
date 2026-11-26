//go:build windows

// The host's resume on Windows (resume.go; §17.8's after sleep, owner decision 789): powrprof's
// PowerRegisterSuspendResumeNotification, from Windows 8 on, calls back on a thread of its own at each suspend and
// resume, for a process as for a service, so the daemon registers once and each resume, PBT_APMRESUMEAUTOMATIC on
// every one and PBT_APMRESUMESUSPEND where a person woke the host, has every bridge read the clock again. Where the
// call is missing or refused, nothing watches, and the bridges' capped waits cover the host.

package main

import (
	"context"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/urnetwork/sidecar"
)

func init() {
	urResumeWatch = urWindowsResumeWatch
}

// powrprof's names: the registration's recipient kind, DEVICE_NOTIFY_CALLBACK, and the power broadcast events a
// resume sends.
const (
	urWindowsDeviceNotifyCallback  = 2
	urWindowsPbtApmResumeSuspend   = 0x0007
	urWindowsPbtApmResumeAutomatic = 0x0012
)

var (
	urWindowsPowrprofDll                              = windows.NewLazySystemDLL("powrprof.dll")
	urWindowsPowerRegisterSuspendResumeNotification   = urWindowsPowrprofDll.NewProc("PowerRegisterSuspendResumeNotification")
	urWindowsPowerUnregisterSuspendResumeNotification = urWindowsPowrprofDll.NewProc("PowerUnregisterSuspendResumeNotification")
)

// DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS: the callback and the context it is called with.
type urWindowsDeviceNotifySubscribeParameters struct {
	Callback uintptr
	Context  uintptr
}

// One watch's resumed, held where the callback finds it by its token's address, which the heap does not move.
type urWindowsResumeWatchEntry struct {
	token   *byte
	resumed func()
}

// powrprof's one callback, made once, since windows.NewCallback's are never freed, and the watches it calls.
var urWindowsResume struct {
	once      sync.Once
	callback  uintptr
	stateLock sync.Mutex
	watches   map[uintptr]*urWindowsResumeWatchEntry
}

// DEVICE_NOTIFY_CALLBACK_ROUTINE: at a resume, calls the watch callbackContext names. Windows calls it on a thread of
// its own and the type is a ULONG, so it reads only that; resumed never blocks. Answers ERROR_SUCCESS.
func urWindowsResumeCallback(callbackContext uintptr, eventType uint32, setting uintptr) uintptr {
	if eventType != urWindowsPbtApmResumeAutomatic && eventType != urWindowsPbtApmResumeSuspend {
		return 0
	}
	urWindowsResume.stateLock.Lock()
	watch := urWindowsResume.watches[callbackContext]
	urWindowsResume.stateLock.Unlock()
	if watch != nil {
		watch.resumed()
	}
	return 0
}

// urResumeWatchFunction over powrprof's suspend and resume notification, until ctx ends.
func urWindowsResumeWatch(ctx context.Context, resumed func(), log sidecar.Logger) {
	if err := urWindowsPowerRegisterSuspendResumeNotification.Find(); err != nil {
		if log.V(1).Enabled() {
			log.Infof("[bridge]no power resume notification: %v", err)
		}
		return
	}
	urWindowsResume.once.Do(func() {
		urWindowsResume.callback = windows.NewCallback(urWindowsResumeCallback)
		urWindowsResume.watches = map[uintptr]*urWindowsResumeWatchEntry{}
	})
	watch := &urWindowsResumeWatchEntry{token: new(byte), resumed: resumed}
	key := uintptr(unsafe.Pointer(watch.token))
	func() {
		urWindowsResume.stateLock.Lock()
		defer urWindowsResume.stateLock.Unlock()
		urWindowsResume.watches[key] = watch
	}()
	defer func() {
		urWindowsResume.stateLock.Lock()
		defer urWindowsResume.stateLock.Unlock()
		delete(urWindowsResume.watches, key)
	}()
	// kept, and pinned, for as long as the registration stands, should powrprof hold it rather than copy it
	parameters := &urWindowsDeviceNotifySubscribeParameters{Callback: urWindowsResume.callback, Context: key}
	pinner := runtime.Pinner{}
	pinner.Pin(parameters)
	defer pinner.Unpin()
	var handle uintptr
	result, _, _ := urWindowsPowerRegisterSuspendResumeNotification.Call(
		urWindowsDeviceNotifyCallback,
		uintptr(unsafe.Pointer(parameters)),
		uintptr(unsafe.Pointer(&handle)),
	)
	if result != 0 {
		if log.V(1).Enabled() {
			log.Infof("[bridge]the power resume notification refused: %v", windows.Errno(result))
		}
		return
	}
	<-ctx.Done()
	urWindowsPowerUnregisterSuspendResumeNotification.Call(handle)
}
