//go:build !sidecar_http && !ios_extension

// The core's own wall-clock ends after a sleep or a clock step (§17.8's after sleep or a clock step, owner decision 789's
// seam; QD-1422): device.Bridge's CheckClock, carried to the core. Each owner below waits for a wall-clock time, an end
// a signed statement or a schedule names, on a runtime timer, which stops while the system sleeps (mach_absolute_time
// on darwin, CLOCK_MONOTONIC on linux), so a device that slept past one, or whose clock stepped forward past one, would
// act on it only when the timer's remaining awake time ran out. Each owner's CheckClock arms its waits again from the
// clock's now and ends at once what lapsed:
//
//	sockets      SocketComponent.CheckClock: each listener's streams, reset with RST_REVOKED at their ticket's
//	             grant_expire_time_millis (socket_listen.go); Sidecar.CheckClock reaches it as a SidecarClockComponent
//	forwards     DaemonBridges.CheckClock: the daemon's port forwards, closed at their grant's expiry
//	             (bridge_daemon_forward.go)
//	forwarding   Forwarder.CheckClock: the forwarding role's follow, compile and the posture's overdue-alarm points
//	             (bridge_forward.go), which the VPN component's DeviceLocal.CheckClock reaches in the sdk
//	shares       DaemonSockets.CheckClock: ur share's shares, ended at their expire_millis (socket_share.go)
//
// Revocations need none: each acts at once, by a policy change, a reread of a grant or the posture's own denial. New
// work needs none either, since each edge reads the wall clock as it admits: a ticket's expiry, a forward's expiry for
// each connection, a share's expire_millis for each get, a flow's rules in the hook. Relative waits, timeouts and
// retries, stay as they are: lateness only makes them wait longer.
//
// Who calls. ur daemon calls every hosted Sidecar's CheckClock, its DaemonBridges' and its DaemonSockets' beside its
// bridges' checks at the host's resume (cli/resume.go: logind's PrepareForSleep(false), powrprof's resume), and, since
// a desktop has no one wake signal Go reads portably and none reaches it on a step of the clock, at the desktop's
// device.BridgeSettings.ClockCheckInterval, the one interval that caps the bridges' own waits, so a desktop is late by
// at most that interval after it wakes. An app's VPN component calls DeviceLocal.CheckClock at each wake and clock
// change, which reaches the bridges and every forwarding role; its forwarding roles take the same desktop interval on
// a desktop, and none on a phone, which adds no periodic wakeup.

package sidecar

// Optional beside SidecarComponent: a component that waits for a wall-clock end reads the clock again at once after a
// sleep or a clock step (the file's comment), arming its waits from now and ending what lapsed. Called from any
// goroutine, the daemon's resume watch's among them: it must not block.
type SidecarClockComponent interface {
	CheckClock()
}

var _ SidecarClockComponent = (*SocketComponent)(nil)

// Has every listed component that waits for a wall-clock end read the clock again at once (the file's comment): the
// sockets component's streams' grant ends among them. Safe from any goroutine and never blocks; a Sidecar with no
// connect leg, or none listed, does nothing.
func (self *Sidecar) CheckClock() {
	if leg, ok := self.leg.(interface{ checkComponentClocks() }); ok {
		leg.checkComponentClocks()
	}
}

// Hands each listed SidecarClockComponent a check.
func (self *sidecarConnectLeg) checkComponentClocks() {
	for _, component := range self.componentList() {
		if clocked, ok := component.(SidecarClockComponent); ok {
			clocked.CheckClock()
		}
	}
}
