// The daemon's events method (§18.5, §5.8; QD-821, question sdk-m8-02-remote-events): a remote-mode app's sdk, and the
// extension through ur native-host, long-poll the ring of the core's events the daemon keeps (sidecar.DaemonEvents,
// the root's daemon_events.go), so every event kind reaches them and not only the state a status read shows. ur daemon
// attaches each Sidecar it starts to that ring (cmd_daemon.go), the unenrolled one a further network's enrollment
// takes among them, and the method registers here beside the daemon's own, over a target whose daemon keeps the ring.

package main

import (
	"github.com/urnetwork/sidecar"
)

func init() {
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urDaemonEventsMethods)
}

// A target whose daemon keeps the events ring.
type urDaemonEventsTarget interface {
	daemonEvents() *sidecar.DaemonEvents
}

// The events method over target's ring, when it keeps one.
func urDaemonEventsMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	eventsTarget, ok := target.(urDaemonEventsTarget)
	if !ok {
		return nil
	}
	events := eventsTarget.daemonEvents()
	if events == nil {
		return nil
	}
	return []*sidecar.DaemonMethod{sidecar.DaemonEventsMethod(events)}
}

// The daemon's events ring, nil for a target running no daemon.
func (self *urDaemonNetwork) daemonEvents() *sidecar.DaemonEvents {
	if self.daemon == nil {
		return nil
	}
	return self.daemon.Events()
}
