// The Forwarder's settings and its compile admission rule (BRIDGE-M8-05; DESIGN-DETAILS 4.2.4, 4.2.5, 12.7; QD-620,
// QD-641): what a VPN component's forwarding role is bounded by while no sidecar role runs.
//
// The role keeps no state in memory between compiles but the pin, its timers and these settings, and a compile is
// transient: it runs only when CompileAdmission passes. The estimate of a compile's memory is CompileEstimateRowsFactor
// times the rows' bytes, since a row decodes into a struct and a separate allocation for each id, key and hash it
// holds, CompileEstimateHeadFactor times the head's bytes, the newest base's tail bytes, CompileEstimateStateFactor
// times the last compiled state's size (12.7, stricter than QD-620's rule) and CompileEstimateOverheadByteCount. Past
// CompileMemoryMaxByteCount the compile never runs on this device (compile_over_budget); under it, with the process's
// heap in use the estimate must fit under CompileHeapCeilingByteCount, or the compile is deferred and retried
// (compile_deferred). Either way the last verified state stays in force and nothing goes pending (QD-621).
//
// The Forwarder itself, its follow, its compile and its key handling are not built yet: this file holds what they are
// bounded by, and bridge_forward_sign.go the signer.

package sidecar

import (
	"fmt"
	"time"
)

// Where a forwarding role runs, which sets its memory bounds (DESIGN-DETAILS 4.2.5's settings).
type ForwarderHostClass string

const (
	// An Apple network extension: the tunnel's 32 MiB soft limit bounds it.
	ForwarderHostApple ForwarderHostClass = "apple"
	// An Android VPN service.
	ForwarderHostAndroid ForwarderHostClass = "android"
	// A desktop service: Windows, Linux, macOS outside an extension.
	ForwarderHostDesktop ForwarderHostClass = "desktop"
)

// The bridge_alarm reasons a forwarding role raises (DESIGN-DETAILS 4.2.5; QD-621).
const (
	// A compile's estimate is past CompileMemoryMaxByteCount: it never runs on this device.
	ForwarderAlarmCompileOverBudget = "compile_over_budget"
	// A compile the heap ceiling has deferred for CompileDeferredAlarmTimeout.
	ForwarderAlarmCompileDeferred = "compile_deferred"
	// A generation's key the forwarding reader key has no wrap for yet.
	ForwarderAlarmConfigKeyWaiting = "config_key_waiting"
	// The forwarding client's credential lapsed.
	ForwarderAlarmForwardClientLapsed = "forward_client_lapsed"
	// A narrowing entry the posture cannot check has waited past its timeout (the posture's PostureAlarmCompileOverdue).
	ForwarderAlarmNarrowingOverdue = "narrowing_overdue"
)

// Tunables of a forwarding role.
type ForwarderSettings struct {
	// How long a compile waits for further hints to coalesce: 2 s.
	CompileDelay time.Duration
	// The least time between one compile's start and the next: 10 s.
	CompileMinInterval time.Duration
	// How long a deferred or failed compile waits before it tries again: 30 s, doubling to CompileRetryMaxInterval,
	// 10 min.
	CompileRetryInterval    time.Duration
	CompileRetryMaxInterval time.Duration
	// How long the heap ceiling may defer a compile before compile_deferred is raised: 10 min.
	CompileDeferredAlarmTimeout time.Duration
	// The most a compile's estimated memory may be: 10 MiB in an Apple extension, 16 MiB on Android, 64 MiB on a
	// desktop service. Non-positive refuses every compile.
	CompileMemoryMaxByteCount int64
	// The most the process's heap in use plus a compile's estimate may be: 30 MiB in an Apple extension, under the
	// tunnel's 32 MiB soft limit; 0 for no ceiling.
	CompileHeapCeilingByteCount int64
	// The estimate's terms (the file's comment): 5, 2, 2 and 1 MiB.
	CompileEstimateRowsFactor        int64
	CompileEstimateHeadFactor        int64
	CompileEstimateStateFactor       int64
	CompileEstimateOverheadByteCount int64
	// How many entries a compile applies at a time after its base: 256.
	CompileApplyRunCount int
	// How often the role follows the log with no hint: 1 h.
	FollowInterval time.Duration
	// How many pages one follow reads before it yields: 64.
	FollowPageMaxCount int
	// How often config_key_waiting is raised while a generation's key is missing: 10 min.
	KeyWaitAlarmInterval time.Duration
	// How many opened heads stay cached on storage: 2.
	HeadCacheCount int
	// Whether a compile returns its memory to the OS when it ends (debug.FreeOSMemory): the mobile classes.
	FreeMemoryAfterCompile bool
}

// The settings for a host class; an unknown class takes the Apple extension's, the tightest.
func DefaultForwarderSettings(hostClass ForwarderHostClass) *ForwarderSettings {
	settings := &ForwarderSettings{
		CompileDelay:                     2 * time.Second,
		CompileMinInterval:               10 * time.Second,
		CompileRetryInterval:             30 * time.Second,
		CompileRetryMaxInterval:          10 * time.Minute,
		CompileDeferredAlarmTimeout:      10 * time.Minute,
		CompileMemoryMaxByteCount:        10 * 1024 * 1024,
		CompileHeapCeilingByteCount:      30 * 1024 * 1024,
		CompileEstimateRowsFactor:        5,
		CompileEstimateHeadFactor:        2,
		CompileEstimateStateFactor:       2,
		CompileEstimateOverheadByteCount: 1024 * 1024,
		CompileApplyRunCount:             256,
		FollowInterval:                   time.Hour,
		FollowPageMaxCount:               64,
		KeyWaitAlarmInterval:             10 * time.Minute,
		HeadCacheCount:                   2,
		FreeMemoryAfterCompile:           true,
	}
	switch hostClass {
	case ForwarderHostAndroid:
		settings.CompileMemoryMaxByteCount = 16 * 1024 * 1024
		settings.CompileHeapCeilingByteCount = 0
	case ForwarderHostDesktop:
		settings.CompileMemoryMaxByteCount = 64 * 1024 * 1024
		settings.CompileHeapCeilingByteCount = 0
		settings.FreeMemoryAfterCompile = false
	}
	return settings
}

// Refuses settings a forwarding role cannot run by.
func (self *ForwarderSettings) Validate() error {
	switch {
	case self.CompileDelay < 0 || self.CompileMinInterval < 0:
		return fmt.Errorf("%w: a forwarder's compile delay or interval is negative", errInvalidSettings)
	case self.CompileRetryInterval <= 0 || self.CompileRetryMaxInterval < self.CompileRetryInterval:
		return fmt.Errorf("%w: a forwarder's compile retry interval", errInvalidSettings)
	case self.CompileEstimateRowsFactor < 1 || self.CompileEstimateHeadFactor < 1 || self.CompileEstimateStateFactor < 0 || self.CompileEstimateOverheadByteCount < 0:
		return fmt.Errorf("%w: a forwarder's compile estimate", errInvalidSettings)
	case self.CompileHeapCeilingByteCount < 0:
		return fmt.Errorf("%w: a forwarder's heap ceiling is negative", errInvalidSettings)
	case self.CompileApplyRunCount <= 0 || self.FollowPageMaxCount <= 0 || self.HeadCacheCount <= 0:
		return fmt.Errorf("%w: a forwarder's run, page or cache count", errInvalidSettings)
	case self.FollowInterval <= 0 || self.KeyWaitAlarmInterval <= 0 || self.CompileDeferredAlarmTimeout <= 0:
		return fmt.Errorf("%w: a forwarder's follow or alarm interval", errInvalidSettings)
	}
	return nil
}

// What a compile would read, in bytes, as the store holds it.
type ForwarderCompileSize struct {
	// The rows-only log's rows at its newest base.
	RowsByteCount int64
	// The head the compile reads.
	HeadByteCount int64
	// The entries after the newest base.
	TailByteCount int64
	// The last compiled state, 0 before the first.
	StateByteCount int64
}

// What the admission rule decides for one compile.
type ForwarderCompileAdmission int

const (
	// The compile may run now.
	ForwarderCompileAdmitted ForwarderCompileAdmission = iota + 1
	// The heap ceiling defers it: retried at CompileRetryInterval, compile_deferred after CompileDeferredAlarmTimeout.
	ForwarderCompileDeferred
	// Its estimate is past the cap: it never runs on this device, compile_over_budget.
	ForwarderCompileOverBudget
)

// A compile's estimated memory (the file's comment). A negative size, or a sum past int64, is the largest estimate, so
// a size nothing could hold is refused.
func (self *ForwarderSettings) CompileEstimate(size ForwarderCompileSize) int64 {
	const most = int64(1<<63 - 1)
	estimate := self.CompileEstimateOverheadByteCount
	for _, term := range [][2]int64{
		{self.CompileEstimateRowsFactor, size.RowsByteCount},
		{self.CompileEstimateHeadFactor, size.HeadByteCount},
		{1, size.TailByteCount},
		{self.CompileEstimateStateFactor, size.StateByteCount},
	} {
		factor, byteCount := term[0], term[1]
		if byteCount < 0 || factor < 0 || estimate < 0 {
			return most
		}
		if factor != 0 && (most-estimate)/factor < byteCount {
			return most
		}
		estimate += factor * byteCount
	}
	return estimate
}

// The admission rule for one compile, with the process's heap in use now: over budget past the cap whatever the
// heap, deferred where the heap and the estimate together pass the ceiling, else admitted.
func (self *ForwarderSettings) CompileAdmission(size ForwarderCompileSize, heapInUseByteCount int64) ForwarderCompileAdmission {
	estimate := self.CompileEstimate(size)
	if self.CompileMemoryMaxByteCount < estimate {
		return ForwarderCompileOverBudget
	}
	if 0 < self.CompileHeapCeilingByteCount && (heapInUseByteCount < 0 || self.CompileHeapCeilingByteCount-estimate < heapInUseByteCount) {
		return ForwarderCompileDeferred
	}
	return ForwarderCompileAdmitted
}

// How long a compile waits before its retryCount-th retry, from 0: CompileRetryInterval doubling to
// CompileRetryMaxInterval.
func (self *ForwarderSettings) CompileRetryTimeout(retryCount int) time.Duration {
	timeout := self.CompileRetryInterval
	for range max(retryCount, 0) {
		if self.CompileRetryMaxInterval <= timeout {
			break
		}
		timeout *= 2
	}
	return min(timeout, self.CompileRetryMaxInterval)
}
