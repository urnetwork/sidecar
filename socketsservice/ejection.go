// §9.6's outlier rules as pure functions, on the same terms as scheduler.go. A report excludes a
// listener for the dialer that made it, and ejection for all needs more: a lying reporter harms only
// itself (D-SOCK-6). Exclusion and ejection last alike, so both are a SocketEjectionState.
//
// A store runs these when a Find carries failed tickets. Who may report, and that an edge reports only
// accept timeouts, is settled before a report gets here.

package socketsservice

import (
	"github.com/urnetwork/connect"
)

// A run of ejections of one listener, or of one dialer's exclusions of it. The zero value is none.
// §9.6 says 30 s per consecutive ejection and never what ends a run, so this reads consecutive by what
// the store may keep: §2.8 lets a record live EjectionMax, so an ejection continues a run only if the
// record of the one before is still there. An ejection at the top of the ladder lasts as long as its
// record, so the next one starts a new run.
type SocketEjectionState struct {
	// How many ejections this run holds, the newest included.
	ConsecutiveCount int
	// When the newest began, in milliseconds.
	StartMillis int64
}

// How long the newest ejection lasts, in milliseconds.
func (self SocketEjectionState) durationMillis(settings *SocketSchedulerSettings) int64 {
	return min(int64(self.ConsecutiveCount)*settings.EjectionStep.Milliseconds(), settings.EjectionMax.Milliseconds())
}

// Whether the newest ejection still holds.
func (self SocketEjectionState) Active(nowMillis int64, settings *SocketSchedulerSettings) bool {
	return nowMillis < self.StartMillis+self.durationMillis(settings)
}

// The state after one more ejection and whether it took, out of a group of groupCount with
// ejectedCount already out. One that holds is left alone, so a late report cannot lengthen it, and the
// group's cap can refuse: at most half of it may be out at once, so a group of one is never ejected.
func (self SocketEjectionState) Eject(nowMillis int64, ejectedCount int, groupCount int, settings *SocketSchedulerSettings) (SocketEjectionState, bool) {
	if self.Active(nowMillis, settings) {
		return self, false
	}
	if groupCount*settings.EjectionGroupPercent < (ejectedCount+1)*100 {
		return self, false
	}
	consecutiveCount := 1
	if self.ConsecutiveCount > 0 && nowMillis < self.StartMillis+settings.EjectionMax.Milliseconds() {
		consecutiveCount = self.ConsecutiveCount + 1
	}
	return SocketEjectionState{ConsecutiveCount: consecutiveCount, StartMillis: nowMillis}, true
}

// One holder's report that a listener failed it, kept until the window below has passed it.
type SocketFailureReport struct {
	DialerNetworkId connect.Id
	ReportMillis    int64
}

// Whether reports are enough to eject for all: reporters from 2 networks within 30 s (§9.6, D-SOCK-6),
// as written. As §9.4 stands that can fire only for ur/ names, whose dialers span networks, and
// question plan-SOCK-ejection-reporters asks whether that is meant. This function alone holds the
// rule, so an answer changes it and its tests. A report from past nowMillis does not count.
func SocketReportersEject(reports []*SocketFailureReport, nowMillis int64, settings *SocketSchedulerSettings) bool {
	reporterWindowMillis := settings.ReporterWindow.Milliseconds()
	networkIds := map[connect.Id]bool{}
	for _, report := range reports {
		if report.ReportMillis <= nowMillis && nowMillis-report.ReportMillis <= reporterWindowMillis {
			networkIds[report.DialerNetworkId] = true
		}
	}
	return settings.ReporterNetworkCount <= len(networkIds)
}
