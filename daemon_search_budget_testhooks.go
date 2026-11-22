//go:build sidecar_testhooks && !ios_extension && !sidecar_http

// D-CORE-17's budget for a search world (sidecartest's search_remote_world.go), its CPU meter apart from its clock: a
// world moves its fake clock for a requester rate's refill or a timeout, and a slot held across that move, a leg its
// requester stopped waiting for, would count all of it as compute on the one clock. Only the sidecar_testhooks build
// has it, which no release leg is (§22.4).

package sidecar

// A budget as NewSidecarRemoteBudget's on clock whose CPU meter is cpuClock, nil for clock itself: RemoteCpuPerMinute's
// charges and a page's PageCpu move only as cpuClock does, while the window, the rate and the queue's waits follow
// clock.
func NewSearchTestRemoteBudget(settings *SidecarSearchSettings, clock Clock, cpuClock Clock) (*SidecarRemoteBudget, error) {
	return newSidecarRemoteBudget(settings, clock, cpuClock)
}
