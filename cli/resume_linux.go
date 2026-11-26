//go:build linux

// The host's resume on Linux (resume.go; §17.8's after sleep, owner decision 789): logind broadcasts PrepareForSleep
// on the system bus, true as the host goes to sleep and false once it has resumed, so the daemon holds one system bus
// connection, the bus ur tun already talks to for systemd-resolved (bridge_dns_linux.go), with a match for that
// signal from logind alone, and each false has every bridge read the clock again. Where there is no system bus, as
// in a container or a WSL2 distribution without systemd, or the bus refuses the match, nothing watches; and a bus
// that goes away ends the watch. The bridges' capped waits cover the host then.

package main

import (
	"context"

	"github.com/godbus/dbus/v5"

	"github.com/urnetwork/sidecar"
)

func init() {
	urResumeWatch = urLinuxResumeWatch
}

// logind's bus names.
const (
	urLogindDestination = "org.freedesktop.login1"
	urLogindPath        = dbus.ObjectPath("/org/freedesktop/login1")
	urLogindManager     = "org.freedesktop.login1.Manager"
	urLogindSleepMember = "PrepareForSleep"
)

// urResumeWatchFunction over logind's PrepareForSleep(false), until ctx ends or the bus goes away.
func urLinuxResumeWatch(ctx context.Context, resumed func(), log sidecar.Logger) {
	conn, err := dbus.ConnectSystemBus(dbus.WithContext(ctx))
	if err != nil {
		if log.V(1).Enabled() {
			log.Infof("[bridge]no system bus for logind's resume: %v", err)
		}
		return
	}
	defer conn.Close()
	// logind's alone: the bus routes a signal under this match only from the name's owner
	err = conn.AddMatchSignalContext(ctx,
		dbus.WithMatchSender(urLogindDestination),
		dbus.WithMatchObjectPath(urLogindPath),
		dbus.WithMatchInterface(urLogindManager),
		dbus.WithMatchMember(urLogindSleepMember),
	)
	if err != nil {
		if log.V(1).Enabled() {
			log.Infof("[bridge]the system bus refused logind's resume match: %v", err)
		}
		return
	}
	// one signal waits; godbus holds any more for a slow reader, and this one never blocks
	signals := make(chan *dbus.Signal, 1)
	conn.Signal(signals)
	defer conn.RemoveSignal(signals)
	for {
		select {
		case <-ctx.Done():
			return
		case signal, ok := <-signals:
			if !ok {
				if log.V(1).Enabled() {
					log.Infof("[bridge]the system bus went away: logind's resume is no longer watched")
				}
				return
			}
			if urLogindResumed(signal) {
				resumed()
			}
		}
	}
}

// Whether signal is logind's PrepareForSleep(false), sent once the host has resumed; the bus's own signals to this
// connection, and PrepareForSleep(true) before a sleep, are not.
func urLogindResumed(signal *dbus.Signal) bool {
	if signal == nil || signal.Path != urLogindPath || signal.Name != urLogindManager+"."+urLogindSleepMember ||
		len(signal.Body) != 1 {
		return false
	}
	start, ok := signal.Body[0].(bool)
	return ok && !start
}
