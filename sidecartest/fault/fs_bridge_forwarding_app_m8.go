//go:build !sidecar_http && !ios_extension

// BRIDGE-M8-07's schedules on an app host (DESIGN-DETAILS 4.6's §22.5 rows, and Fwd.tla's twins and its accepted trace
// on real code; FS-38, FI-11, D-BRIDGE-17, D-BRIDGE-18, D-SDK-32, I-3, I-4, QD-621, QD-696, owner decision 197): BridgeNet's
// StartAppHost, a host whose device role its own Forwarder feeds while no sidecar role runs, as an app's VPN component's
// is while the app sleeps. Each subject is folded into a base before the host starts, so the posture checks what it
// signs; a device admitted after that base signs what the posture cannot check. On T2 here, and on T3 through server's
// controller (server/controller/connect_bridge_forwarding_test.go), which answers every contract:
//
//	admitted           a window its subject's forwarding key signed opens TCP, UDP and ICMP at the app host, and a
//	                   connection it opened carries on: the twin of every refusal below
//	within targets     with the Forwarder's own CompileDelay and CompileMinInterval, a new forwarding Delegation is
//	                   admitted CompileDelay after its hint and not before (the overlay opens nothing, Fwd.tla's
//	                   OverlayOpens), and its DelegationRevoke ends its key's flows at once, with no compile and no
//	                   time passing (NoDelegationOverlay)
//	revoke vs compile  a compile captured below a DelegationRevoke is held while the revocation lands; let go, it hands
//	                   its state, the revocation applies right after it with no compile of its own, and one more
//	                   compile follows for the hint it missed
//	supersede vs       with compiles held, a newer forwarding Delegation's supersession ends the old key's connection,
//	  contract         a contract the old key's window makes after it opens nothing, and the new key opens nothing until
//	                   the compile that judged it
//	lower state        a compile below the state in force, from a restarted Forwarder over a lost store and an api
//	                   withholding the revocation, is dropped (LowerStateAccepted)
//	overlay kept       the same compile above the state in force but below an overlay revocation is taken, and the
//	                   revocation stands above it (StateDropsOverlay)
//	unsuspend          a Suspend denies the subject at once; an Unsuspend lifts nothing until a compile judges it
//	                   (OverlayLifts); one the rule table refuses, which a malicious api sequenced, lifts nothing even
//	                   then (T2 alone)
//	no compile         compiles deferred by the heap, an uncheckable revocation leaves the key admitted and the state in
//	                   force: narrowing_overdue at 10 min with its position and age, a second uncheckable entry's own at
//	                   once when it becomes overdue (RepeatsOnly), the repeat at 30, the condition standing throughout,
//	                   and the first compile let run applies the revocation and clears it (FwdReach-NoCompile, QD-621,
//	                   QD-696); over the memory cap, the same with no compile ever, and never pending
//	rollback           a posture store put back below the floor is pending, every flow refused, until a compile brings
//	                   the pin back (NoFloor); its twin restarts with no rollback
//
// None of these is in the fault catalog, as fs_bridge_forwarding_m8.go says for FS-38's forwarding rows: §23.6's M8 row
// names §22.5's forwarding cases and no FS case, so each runs as a schedule of its own until a design-records fold of
// DESIGN-DETAILS 4.6 gives it one. The Forwarder's alarm timer is waited on by a hint after each clock move, as F's
// long-poll would wake it, since nothing outside the Forwarder can see that its loop has armed its timer; the root's
// bridge_forward tests hold the timer's own waking.

package fault

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/device"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// FS-38's forwarding rows at an app host, each refusal beside the twin that admits.
var (
	FwdAppWithinTargetsCase          = Twin(FwdAppWithinTargets, FwdAppHostAdmits)
	FwdAppRevokeRacesCompileCase     = Twin(FwdAppRevokeRacesCompile, FwdAppHostAdmits)
	FwdAppSupersedeRacesContractCase = Twin(FwdAppSupersedeRacesContract, FwdAppHostAdmits)
	FwdAppLowerStateDroppedCase      = Twin(FwdAppLowerStateDropped, FwdAppHostAdmits)
	FwdAppStateKeepsOverlayCase      = Twin(FwdAppStateKeepsOverlay, FwdAppHostAdmits)
	FwdAppUnsuspendWaitsCase         = Twin(FwdAppUnsuspendWaitsForACompile, FwdAppHostAdmits)
	FwdAppRefusedUnsuspendCase       = Twin(FwdAppRefusedUnsuspend, FwdAppHostAdmits)
	FwdAppNoCompileCase              = Twin(FwdAppNoCompileOverdue, FwdAppHostAdmits)
	FwdAppOverCapCase                = Twin(FwdAppOverCapNeverPending, FwdAppHostAdmits)
	FwdAppRollbackCase               = Twin(FwdAppRollbackIsPending, FwdAppRestartKeepsTheState)
)

// A connection through a window, under a name a builder's net parameter does not shadow.
type fsAppConn = net.Conn

// The app host's heap ceiling for the schedules that defer compiles: an Apple extension's, under its 32 MiB tunnel.
const fsAppHeapCeilingByteCount = 30 * 1024 * 1024

// The first step of an app host's schedule: the network, whose windows' delegations outlive the hours a schedule's
// clock moves; the subjects named; every device folded into a base, so the posture checks what each signs; and the app
// host at the host's address, its Forwarder edited by edit, nil for none.
func fsAppSetup(world *fsBridgeWorld, edit func(settings *sidecartest.BridgeNetAppHostSettings), subjectNames ...string) *Step {
	return &Step{Actor: "setup", Action: func(ctx context.Context, net *Net) error {
		return fsTeamCatch(func() error {
			settings := sidecartest.DefaultBridgeNetSettings()
			if tier := sidecartest.NetBridgeSettings(net); tier != nil {
				copied := *tier
				settings = &copied
			}
			settings.DelegationLifetime = 24 * time.Hour
			world.world = sidecartest.NewBridgeNet(fsTeamFailer{}, net, settings)
			hostDevice := world.world.AddDevice("host")
			for _, name := range subjectNames {
				world.subjects[name] = world.world.AddDevice(name)
			}
			world.world.Admission().Fold(true)
			hostSettings := &sidecartest.BridgeNetAppHostSettings{Address: fsBridgeHostAddress}
			if edit != nil {
				edit(hostSettings)
			}
			world.host = world.world.StartAppHost(hostDevice, hostSettings)
			if world.host.ComponentStatus().CompiledPin != nil {
				return errors.New("an app host ran a sidecar role's component")
			}
			return nil
		})
	}}
}

// An app host's schedule: fsBridgeSchedule's, on T2 and T3.
func fsAppSchedule(refuses string, world *fsBridgeWorld, steps ...*Step) *Schedule {
	return fsBridgeSchedule("FS-38", refuses, world, steps...)
}

// The subject's forwarding Delegation, filed and compiled at the host.
func fsAppForward(world *fsBridgeWorld, subjectName string, label string) (*sidecartest.BridgeNetForwarding, error) {
	forwarding := world.world.FileForwarding(world.subjects[subjectName], label)
	world.world.Follow()
	return forwarding, fsForwardingCompiled(world, forwarding)
}

// A TCP connection through window to the host's upstream, its first bytes payload delivered there.
func fsAppConnect(world *fsBridgeWorld, window *sidecartest.BridgeNetWindow, payload string) (fsAppConn, error) {
	conn, err := window.DialTcp(netip.AddrPortFrom(world.host.Address, world.host.Upstream.TcpPort()))
	if err != nil {
		return nil, fmt.Errorf("%s's TCP connection: %w", window.Name, err)
	}
	if _, err := conn.Write([]byte(payload)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("%s's first bytes: %w", window.Name, err)
	}
	if !world.host.Upstream.WaitFor(world.world.Settings().WaitTimeout, func(accepts []sidecartest.BridgeNetAccept, datagrams [][]byte) bool {
		_, ok := fsForwardingAccept(accepts, payload)
		return ok
	}) {
		conn.Close()
		return nil, fmt.Errorf("%s's first bytes never reached the upstream", window.Name)
	}
	return conn, nil
}

// The connection whose first bytes were payload carries more, still open at the upstream.
func fsAppCarries(world *fsBridgeWorld, conn fsAppConn, payload string, more string) error {
	if _, err := conn.Write([]byte(more)); err != nil {
		return fmt.Errorf("the connection that began %q: %w", payload, err)
	}
	if !world.host.Upstream.WaitFor(world.world.Settings().WaitTimeout, func(accepts []sidecartest.BridgeNetAccept, datagrams [][]byte) bool {
		accept, ok := fsForwardingAccept(accepts, payload)
		return ok && strings.HasSuffix(string(accept.Bytes), more) && !accept.Closed
	}) {
		return fmt.Errorf("the connection that began %q stopped carrying bytes", payload)
	}
	return nil
}

// The upstream socket of the connection whose first bytes were payload closed.
func fsAppClosed(world *fsBridgeWorld, payload string) error {
	if !world.host.Upstream.WaitFor(world.world.Settings().WaitTimeout, func(accepts []sidecartest.BridgeNetAccept, datagrams [][]byte) bool {
		accept, ok := fsForwardingAccept(accepts, payload)
		return ok && accept.Closed
	}) {
		return fmt.Errorf("the connection that began %q outlived the end of what admitted it", payload)
	}
	return nil
}

// A window that opens no connection: its TCP dial is refused, and the NAT dials nothing new for it.
func fsAppRefused(world *fsBridgeWorld, window *sidecartest.BridgeNetWindow) error {
	dialsBefore := len(world.host.Dials())
	if conn, err := window.DialTcp(netip.AddrPortFrom(world.host.Address, world.host.Upstream.TcpPort())); err == nil {
		conn.Close()
		return fmt.Errorf("%s opened a connection", window.Name)
	}
	if dials := world.host.Dials(); len(dials) != dialsBefore {
		return fmt.Errorf("%s's refused connection made %d upstream dials", window.Name, len(dials)-dialsBefore)
	}
	return nil
}

// Moves the Net's clock to at and hints the host, so its Forwarder runs at that time whether or not its loop had
// armed its timer before the move (the file's comment).
func fsAppAdvanceTo(world *fsBridgeWorld, at time.Time) {
	world.world.Net().Clock().AdvanceTo(at)
	world.host.Hint()
}

// The state the role enforces: its pin, 0 for none.
func fsAppStatePin(world *fsBridgeWorld) uint64 {
	return world.host.State().GetAuth().GetVersion()
}

// Whether the host's state lists subject's forwarding Delegation as forwarding's.
func fsAppStateLists(world *fsBridgeWorld, forwarding *sidecartest.BridgeNetForwarding) bool {
	for _, identity := range world.host.State().GetIdentities() {
		if bytes.Equal(identity.GetSidecarId(), forwarding.Subject.SidecarId().Bytes()) {
			return bytes.Equal(identity.GetForwardDelegationId(), forwarding.DelegationId)
		}
	}
	return false
}

// FS-38's forwarding twin at an app host, with no sidecar role running: the subject's forwarding key admits its
// window over TCP, UDP and ICMP, the compile that admitted it the Forwarder's own, and a connection it opened carries
// on.
func FwdAppHostAdmits(net *Net) *Schedule {
	world := newFsBridgeWorld()
	var forwarding *sidecartest.BridgeNetForwarding
	return fsAppSchedule("", world,
		fsAppSetup(world, nil, "subject"),
		fsBridgeDo("subject", world, func() error {
			var err error
			forwarding, err = fsAppForward(world, "subject", "app admits")
			return err
		}),
		fsBridgeDo("window", world, func() error {
			window := fsForwardingWindow(world, "app forwarding", world.subjects["subject"], forwarding, nil, nil)
			if err := (&fsBridgeFlows{world: world, window: window}).expectOpen("app forwarding"); err != nil {
				return err
			}
			principals := world.host.Principals(window.Client.ClientId)
			if len(principals) == 0 || principals[0].Principal == nil ||
				principals[0].Principal.Subject != connect.Id(world.subjects["subject"].SidecarId()) {
				return fmt.Errorf("the app host verified no principal of the subject: %+v", principals)
			}
			if status := world.host.Forwarder().Status(); status.CompileCount == 0 || status.CompiledPin.GetVersion() < forwarding.At {
				return fmt.Errorf("the app host's state is no compile of its Forwarder's: %+v", status)
			}
			conn, err := fsAppConnect(world, window, "admitted before;")
			if err != nil {
				return err
			}
			defer conn.Close()
			return fsAppCarries(world, conn, "admitted before;", "admitted after;")
		}),
	)
}

// A grant and a revocation within §8.9's targets at the Forwarder's own timing: CompileDelay 2 s and
// CompileMinInterval 10 s. A new forwarding Delegation opens nothing before its compile and is admitted CompileDelay
// after its hint; its DelegationRevoke ends the key's connection at once, with no compile and no time passing.
func FwdAppWithinTargets(net *Net) *Schedule {
	world := newFsBridgeWorld()
	var forwarding *sidecartest.BridgeNetForwarding
	var conn fsAppConn
	defaults := sidecar.DefaultForwarderSettings(sidecar.ForwarderHostApple)
	return fsAppSchedule("a revoked forwarding key's flows end with no compile and no time passing", world,
		fsAppSetup(world, nil, "subject"),
		fsBridgeDo("host", world, func() error {
			// the component's process restarts with the Forwarder's own timing
			world.host.RestartForwarder(&sidecartest.BridgeNetForwarderRestart{Forwarder: func(settings *sidecar.ForwarderSettings) {
				settings.CompileDelay = defaults.CompileDelay
				settings.CompileMinInterval = defaults.CompileMinInterval
			}})
			world.world.Follow()
			return nil
		}),
		fsBridgeDo("subject", world, func() error {
			clock := world.world.Net().Clock()
			forwarding = world.world.FileForwarding(world.subjects["subject"], "app within targets")
			heard := clock.Now()
			world.host.WaitApplied(forwarding.At)
			early := fsForwardingWindow(world, "app grant early", world.subjects["subject"], forwarding, nil, nil)
			defer early.Close()
			if err := fsAppRefused(world, early); err != nil {
				return fmt.Errorf("a forwarding Delegation the posture took but no compile judged: %w", err)
			}
			if fsAppStateLists(world, forwarding) {
				return errors.New("the state lists the new forwarding Delegation before a compile")
			}
			// the Forwarder wants the compile from a reading taken before the posture took the grant, at heard since
			// nothing moved the clock after it, so one move reaches the compile's due time however late the Forwarder's
			// goroutine runs after the posture shows the pin (sidecar.Forwarder's wantCompileAt)
			fsAppAdvanceTo(world, heard.Add(defaults.CompileDelay))
			world.host.WaitAdopted(forwarding.At)
			if took := clock.Now().Sub(heard); 5*time.Second < took {
				return fmt.Errorf("the grant took %s, past §8.9's p99", took)
			}
			if !fsAppStateLists(world, forwarding) {
				return errors.New("the compile after CompileDelay does not list the forwarding Delegation")
			}
			window := fsForwardingWindow(world, "app grant", world.subjects["subject"], forwarding, nil, nil)
			var err error
			conn, err = fsAppConnect(world, window, "granted;")
			return err
		}),
		fsBridgeDo("subject", world, func() error {
			defer conn.Close()
			clock := world.world.Net().Clock()
			compiles := world.host.Forwarder().Status().CompileCount
			before := clock.Now()
			revokedAt := world.world.RevokeForwarding(world.subjects["subject"], forwarding)
			// api's landing moves its clock a second; nothing after it moves the clock
			landed := clock.Now()
			world.host.WaitApplied(revokedAt)
			if err := fsAppClosed(world, "granted;"); err != nil {
				return err
			}
			if status := world.host.Forwarder().Status(); status.CompileCount != compiles {
				return fmt.Errorf("the revocation waited for %d compiles", status.CompileCount-compiles)
			}
			if now := clock.Now(); !now.Equal(landed) || 2*time.Second < now.Sub(before) {
				return fmt.Errorf("the revocation took the clock from %s to %s", before, now)
			}
			late := fsForwardingWindow(world, "app revoked", world.subjects["subject"], forwarding, nil, nil)
			defer late.Close()
			return fsAppRefused(world, late)
		}),
	)
}

// A DelegationRevoke racing a compile: a compile captured below the revocation is held at its admission while the
// revocation lands and is hinted; let go, its state is handed, the revocation then applies as a denial with no compile
// of its own, ending the key's connection while the identity key's carries on, and one more compile confirms it.
func FwdAppRevokeRacesCompile(net *Net) *Schedule {
	world := newFsBridgeWorld()
	var forwarding *sidecartest.BridgeNetForwarding
	var forwardConn, identityConn fsAppConn
	return fsAppSchedule("a DelegationRevoke landing during a compile ends its key's flows once the compile hands its state", world,
		fsAppSetup(world, nil, "subject", "other"),
		fsBridgeDo("subject", world, func() error {
			var err error
			if forwarding, err = fsAppForward(world, "subject", "app race compile"); err != nil {
				return err
			}
			forwardWindow := fsForwardingWindow(world, "app race forwarding", world.subjects["subject"], forwarding, nil, nil)
			identityWindow := world.world.OpenWindow("app race identity", world.subjects["subject"], world.host, nil)
			if forwardConn, err = fsAppConnect(world, forwardWindow, "race forward;"); err != nil {
				return err
			}
			identityConn, err = fsAppConnect(world, identityWindow, "race identity;")
			return err
		}),
		fsBridgeDo("host", world, func() error {
			// an opening the posture wants a compile for, whose compile is held once it has captured the tip
			world.host.HoldCompiles()
			arrivals := world.host.CompileArrivals()
			world.world.FileForwarding(world.subjects["other"], "app race other")
			world.host.Hint()
			world.host.WaitCompileArrivals(arrivals + 1)
			return nil
		}),
		fsBridgeDo("subject", world, func() error {
			defer forwardConn.Close()
			defer identityConn.Close()
			captured := world.world.Admission().Tip().GetVersion()
			revokedAt := world.world.RevokeForwarding(world.subjects["subject"], forwarding)
			world.host.Hint()
			// the compile holds the Forwarder's one goroutine: the revocation waits behind it
			if pin := world.host.Bridge.Decision().Pin.GetVersion(); revokedAt <= pin {
				return fmt.Errorf("the posture took the revocation at %d during the compile, at %d", revokedAt, pin)
			}
			world.host.ReleaseCompiles()
			world.host.WaitApplied(revokedAt)
			if err := fsAppClosed(world, "race forward;"); err != nil {
				return err
			}
			if err := fsAppCarries(world, identityConn, "race identity;", "race identity after;"); err != nil {
				return err
			}
			// the held compile's state, below the revocation, is in force with the revocation above it: the denial
			// needed no compile of its own
			if statePin := fsAppStatePin(world); statePin < captured || revokedAt <= statePin {
				return fmt.Errorf("the state in force stands at %d, not the held compile's %d below the revocation at %d", statePin, captured, revokedAt)
			}
			if !slices.ContainsFunc(world.host.Bridge.Decision().Overlay, func(entry device.PostureOverlayEntry) bool {
				return entry.Kind == device.PostureOverlayDelegationRevoke && entry.N == revokedAt
			}) {
				return fmt.Errorf("the revocation at %d is not over the state at %d", revokedAt, fsAppStatePin(world))
			}
			late := fsForwardingWindow(world, "app race late", world.subjects["subject"], forwarding, nil, nil)
			defer late.Close()
			return fsAppRefused(world, late)
		}),
	)
}

// A supersession racing a contract: with compiles held, the subject's newer forwarding Delegation lands; the posture
// applies its supersession as a denial, ending the old key's connection, so a contract the old key's window makes
// after it opens nothing, and the new key opens nothing until the compile that judged its Delegation, which then
// admits it while the old key stays refused.
func FwdAppSupersedeRacesContract(net *Net) *Schedule {
	world := newFsBridgeWorld()
	var old, newer *sidecartest.BridgeNetForwarding
	var oldConn fsAppConn
	return fsAppSchedule("a superseded forwarding key opens nothing on a contract made after its supersession, and the newer key only after a compile", world,
		fsAppSetup(world, nil, "subject"),
		fsBridgeDo("subject", world, func() error {
			var err error
			if old, err = fsAppForward(world, "subject", "app supersede old"); err != nil {
				return err
			}
			oldConn, err = fsAppConnect(world, fsForwardingWindow(world, "app supersede old", world.subjects["subject"], old, nil, nil), "superseded;")
			return err
		}),
		fsBridgeDo("subject", world, func() error {
			defer oldConn.Close()
			world.host.HoldCompiles()
			arrivals := world.host.CompileArrivals()
			newer = world.world.FileForwarding(world.subjects["subject"], "app supersede newer")
			world.host.WaitApplied(newer.At)
			world.host.WaitCompileArrivals(arrivals + 1)
			if err := fsAppClosed(world, "superseded;"); err != nil {
				return err
			}
			for name, forwarding := range map[string]*sidecartest.BridgeNetForwarding{"the superseded key": old, "the newer key": newer} {
				window := fsForwardingWindow(world, "app supersede "+name, world.subjects["subject"], forwarding, nil, nil)
				err := fsAppRefused(world, window)
				window.Close()
				if err != nil {
					return fmt.Errorf("%s before the compile: %w", name, err)
				}
			}
			world.host.ReleaseCompiles()
			world.host.WaitAdopted(newer.At)
			if !fsAppStateLists(world, newer) {
				return errors.New("the compile after the supersession does not list the newer Delegation")
			}
			stale := fsForwardingWindow(world, "app supersede stale", world.subjects["subject"], old, nil, nil)
			defer stale.Close()
			if err := fsAppRefused(world, stale); err != nil {
				return fmt.Errorf("the superseded key after the compile: %w", err)
			}
			conn, err := fsAppConnect(world, fsForwardingWindow(world, "app supersede newer", world.subjects["subject"], newer, nil, nil), "newer;")
			if err != nil {
				return err
			}
			return conn.Close()
		}),
	)
}

// The steps the lower-state schedules share: the subject's forwarding Delegation compiled, and an opening after it
// the posture has taken and no compile judged, since the Forwarder restarted with a delay no schedule waits out. Its
// position is what a lagging api serves through later.
func fsAppLowerStateSteps(world *fsBridgeWorld, forwarding **sidecartest.BridgeNetForwarding, opening *uint64) []*Step {
	return []*Step{
		fsAppSetup(world, nil, "subject", "other"),
		fsBridgeDo("subject", world, func() error {
			var err error
			*forwarding, err = fsAppForward(world, "subject", "app lower state")
			return err
		}),
		fsBridgeDo("host", world, func() error {
			world.host.RestartForwarder(&sidecartest.BridgeNetForwarderRestart{Forwarder: func(settings *sidecar.ForwarderSettings) {
				settings.CompileDelay = 24 * time.Hour
			}})
			*opening = world.world.FileForwarding(world.subjects["other"], "app lower state other").At
			world.host.WaitApplied(*opening)
			if statePin := fsAppStatePin(world); *opening <= statePin {
				return fmt.Errorf("the opening at %d was compiled: the state stands at %d", *opening, statePin)
			}
			return nil
		}),
	}
}

// A restart of the Forwarder over a lost store and an api serving the log through the opening alone, withholding what
// came after it: the projection, which the schedule catches up later.
func fsAppLaggingRestart(world *fsBridgeWorld, opening uint64) *sidecartest.BridgeNetLaggingProjection {
	var lagging *sidecartest.BridgeNetLaggingProjection
	world.host.RestartForwarder(&sidecartest.BridgeNetForwarderRestart{
		FreshStore: true,
		Forwarder: func(settings *sidecar.ForwarderSettings) {
			settings.CompileDelay = 0
		},
		Projection: func(api sidecar.ConfigProjectionReader) sidecar.ConfigProjectionReader {
			lagging = sidecartest.NewBridgeNetLaggingProjection(api, opening)
			return lagging
		},
	})
	return lagging
}

// The restarted Forwarder's compile below the posture's pin: its judge holds the stored log to the pin the sink holds
// and refuses it, raising state_unverified and handing the sink nothing, so the state in force and everything above it
// stand. Then api catches up, the retry compiles at the tip, and the key stays refused.
func fsAppBelowThePin(world *fsBridgeWorld, lagging *sidecartest.BridgeNetLaggingProjection, forwarding *sidecartest.BridgeNetForwarding,
	statePin uint64, opening uint64,
) error {
	deadline := time.Now().Add(world.world.Settings().WaitTimeout)
	for world.host.Forwarder().Status().CompileErrorCount == 0 {
		if time.Now().After(deadline) {
			return fmt.Errorf("the restarted Forwarder judged nothing below the pin: %+v", world.host.Forwarder().Status())
		}
		world.host.Hint()
		<-time.After(world.world.Settings().PollInterval)
	}
	status := world.host.Forwarder().Status()
	if status.CompileCount != 0 || !slices.ContainsFunc(status.Alarms, func(alarm sidecar.BridgeAlarm) bool {
		return alarm.Reason == sidecar.SidecarBridgeAlarmStateUnverified
	}) {
		return fmt.Errorf("a compile at %d, below the posture's pin, was handed to it: %+v", opening, status)
	}
	if pin := fsAppStatePin(world); pin != statePin {
		return fmt.Errorf("the state in force moved from %d to %d", statePin, pin)
	}
	window := fsForwardingWindow(world, "app below the pin", forwarding.Subject, forwarding, nil, nil)
	err := fsAppRefused(world, window)
	window.Close()
	if err != nil {
		return fmt.Errorf("the revoked key while api withholds the revocation: %w", err)
	}
	// api catches up, and the retry compiles at the tip
	tip := world.world.Admission().Tip().GetVersion()
	lagging.SetThrough(tip)
	fsAppAdvanceTo(world, world.world.Net().Clock().Now().Add(sidecar.DefaultForwarderSettings(sidecar.ForwarderHostApple).CompileRetryInterval))
	world.host.WaitAdopted(tip)
	if fsAppStateLists(world, forwarding) {
		return errors.New("the compile at the tip lists the revoked Delegation")
	}
	late := fsForwardingWindow(world, "app below the pin caught up", forwarding.Subject, forwarding, nil, nil)
	defer late.Close()
	return fsAppRefused(world, late)
}

// Fwd.tla's LowerStateAccepted on real code: with the revocation compiled into the state in force, a restarted
// Forwarder over a lost store and an api withholding the revocation cannot compile below the posture's pin, so no
// lower state reaches the posture (whose own drop of one is device's TestALowerStateIsDropped), and the revoked key
// stays refused, then and once api catches up.
func FwdAppLowerStateDropped(net *Net) *Schedule {
	world := newFsBridgeWorld()
	var forwarding *sidecartest.BridgeNetForwarding
	var opening uint64
	steps := fsAppLowerStateSteps(world, &forwarding, &opening)
	steps = append(steps,
		fsBridgeDo("subject", world, func() error {
			world.host.RestartForwarder(&sidecartest.BridgeNetForwarderRestart{Forwarder: func(settings *sidecar.ForwarderSettings) {
				settings.CompileDelay = 0
			}})
			revokedAt := world.world.RevokeForwarding(world.subjects["subject"], forwarding)
			world.host.WaitApplied(revokedAt)
			// a base after the revocation, which a compile judges, carries the state past it
			folded := world.world.Admission().Fold(true).GetVersion()
			world.host.WaitAdopted(folded)
			if fsAppStateLists(world, forwarding) || fsAppStatePin(world) < folded {
				return fmt.Errorf("the state at %d after the revocation at %d lists the revoked Delegation", fsAppStatePin(world), revokedAt)
			}
			return fsAppBelowThePin(world, fsAppLaggingRestart(world, opening), forwarding, fsAppStatePin(world), opening)
		}),
	)
	return fsAppSchedule("no compile below the state in force, where a revoked key lives, reaches the posture", world, steps...)
}

// Fwd.tla's StateDropsOverlay on real code: with the revocation an overlay entry above the state in force, the same
// restart's compile at the opening, above the state and below the revocation, is refused below the posture's pin, so
// the overlay stands over the state and the key stays refused (the posture's keeping of an overlay above a state it
// takes is device's TestAStateKeepsTheOverlayAboveItsPin); once api catches up, the compile at the tip confirms it.
func FwdAppStateKeepsOverlay(net *Net) *Schedule {
	world := newFsBridgeWorld()
	var forwarding *sidecartest.BridgeNetForwarding
	var opening uint64
	steps := fsAppLowerStateSteps(world, &forwarding, &opening)
	steps = append(steps,
		fsBridgeDo("subject", world, func() error {
			stateBefore := fsAppStatePin(world)
			revokedAt := world.world.RevokeForwarding(world.subjects["subject"], forwarding)
			world.host.WaitApplied(revokedAt)
			if fsAppStatePin(world) != stateBefore {
				return errors.New("a compile ran for the revocation")
			}
			if !slices.ContainsFunc(world.host.Bridge.Decision().Overlay, func(entry device.PostureOverlayEntry) bool {
				return entry.Kind == device.PostureOverlayDelegationRevoke && entry.N == revokedAt
			}) {
				return fmt.Errorf("the revocation at %d is not over the state at %d", revokedAt, stateBefore)
			}
			return fsAppBelowThePin(world, fsAppLaggingRestart(world, opening), forwarding, stateBefore, opening)
		}),
	)
	return fsAppSchedule("a revocation overlaying the state in force stands while api withholds it from a restarted Forwarder", world, steps...)
}

// A suspend_id from a label: 16 bytes, as §8.8's Suspend carries.
func fsAppSuspendId(world *fsBridgeWorld, label string) []byte {
	return world.world.Admission().Id("app suspend " + label).Bytes()
}

// The steps the Unsuspend schedules share: the subject's forwarding key admitted, then the owner's Suspend of the
// subject denying its window at once; the Forwarder restarts with a delay no schedule waits out, so what follows is
// judged by no compile until the schedule says.
func fsAppSuspendSteps(world *fsBridgeWorld, forwarding **sidecartest.BridgeNetForwarding, suspendId *[]byte) []*Step {
	return []*Step{
		fsAppSetup(world, nil, "subject"),
		fsBridgeDo("subject", world, func() error {
			var err error
			*forwarding, err = fsAppForward(world, "subject", "app suspend")
			return err
		}),
		fsBridgeDo("owner", world, func() error {
			world.host.RestartForwarder(&sidecartest.BridgeNetForwarderRestart{Forwarder: func(settings *sidecar.ForwarderSettings) {
				settings.CompileDelay = 24 * time.Hour
			}})
			admission := world.world.Admission()
			*suspendId = fsAppSuspendId(world, "subject")
			subject := world.subjects["subject"].Device
			suspendedAt := world.world.Land(admission.Owner(), bridge.SignedType_SIGNED_SUSPEND, &bridge.Suspend{
				Header: admission.Header(), Subject: subject.SidecarId.Bytes(), SuspendId: *suspendId,
			})
			world.host.WaitApplied(suspendedAt)
			window := fsForwardingWindow(world, "app suspended", world.subjects["subject"], *forwarding, nil, nil)
			defer window.Close()
			if err := fsAppRefused(world, window); err != nil {
				return fmt.Errorf("the subject's key under its Suspend: %w", err)
			}
			return nil
		}),
	}
}

// Fwd.tla's OverlayLifts on real code: the owner's Unsuspend lifts nothing while no compile has judged it, and the
// compile that judges it opens the subject's key again.
func FwdAppUnsuspendWaitsForACompile(net *Net) *Schedule {
	world := newFsBridgeWorld()
	var forwarding *sidecartest.BridgeNetForwarding
	var suspendId []byte
	steps := fsAppSuspendSteps(world, &forwarding, &suspendId)
	steps = append(steps,
		fsBridgeDo("owner", world, func() error {
			admission := world.world.Admission()
			subject := world.subjects["subject"].Device
			liftedAt := world.world.Land(admission.Owner(), bridge.SignedType_SIGNED_UNSUSPEND, &bridge.Unsuspend{
				Header: admission.Header(), Subject: subject.SidecarId.Bytes(), SuspendId: suspendId,
			})
			world.host.WaitApplied(liftedAt)
			window := fsForwardingWindow(world, "app unsuspend uncompiled", world.subjects["subject"], forwarding, nil, nil)
			err := fsAppRefused(world, window)
			window.Close()
			if err != nil {
				return fmt.Errorf("an Unsuspend no compile judged: %w", err)
			}
			world.host.RestartForwarder(&sidecartest.BridgeNetForwarderRestart{Forwarder: func(settings *sidecar.ForwarderSettings) {
				settings.CompileDelay = 0
			}})
			world.host.WaitAdopted(liftedAt)
			conn, err := fsAppConnect(world, fsForwardingWindow(world, "app unsuspended", world.subjects["subject"], forwarding, nil, nil), "unsuspended;")
			if err != nil {
				return fmt.Errorf("the compile that judged the Unsuspend: %w", err)
			}
			return conn.Close()
		}),
	)
	return fsAppSchedule("an Unsuspend no compile has judged lifts nothing at an app host", world, steps...)
}

// The refused Unsuspend (Fwd.tla's OverlayLifts with ok false): one the subject signed for itself, which the rule table
// refuses and a malicious api sequences anyway, lifts nothing, neither before a compile nor after the compile that
// judges it. T2 alone: only T2's api appends what its own check refuses.
func FwdAppRefusedUnsuspend(net *Net) *Schedule {
	world := newFsBridgeWorld()
	var forwarding *sidecartest.BridgeNetForwarding
	var suspendId []byte
	steps := fsAppSuspendSteps(world, &forwarding, &suspendId)
	steps = append(steps,
		fsBridgeDo("api", world, func() error {
			admission := world.world.Admission()
			subject := world.subjects["subject"].Device
			signed := admission.Sign(subject, bridge.SignedType_SIGNED_UNSUSPEND, &bridge.Unsuspend{
				Header: admission.Header(), Subject: subject.SidecarId.Bytes(), SuspendId: suspendId,
			})
			refusedAt := admission.SequenceAnyway(bridge.AuthEntryKindStatement, signed).GetVersion()
			if verdict := admission.VerdictAt(refusedAt); verdict.Accepted() {
				return errors.New("the rule table took the subject's own Unsuspend")
			}
			world.host.WaitApplied(refusedAt)
			for _, compiled := range []bool{false, true} {
				if compiled {
					world.host.RestartForwarder(&sidecartest.BridgeNetForwarderRestart{Forwarder: func(settings *sidecar.ForwarderSettings) {
						settings.CompileDelay = 0
					}})
					world.host.WaitAdopted(refusedAt)
				}
				window := fsForwardingWindow(world, fmt.Sprintf("app refused unsuspend compiled %t", compiled), world.subjects["subject"], forwarding, nil, nil)
				err := fsAppRefused(world, window)
				window.Close()
				if err != nil {
					return fmt.Errorf("the refused Unsuspend, compiled %t: %w", compiled, err)
				}
			}
			return nil
		}),
	)
	schedule := fsAppSchedule("an Unsuspend the rule table refuses lifts nothing at an app host, compiled or not", world, steps...)
	schedule.Tiers = []Tier{TierT2}
	schedule.Forged = true
	return schedule
}

// The steps the no-compile schedules share: the subject's forwarding key admitted with a live connection, a second
// subject's too, and an admin's late device, admitted after the base the posture holds, so the posture cannot check
// what it signs; then compiles are blocked by block.
func fsAppNoCompileSteps(world *fsBridgeWorld, forwardings map[string]*sidecartest.BridgeNetForwarding, conn *fsAppConn,
	late **sidecartest.AdmissionDevice, block func(),
) []*Step {
	return []*Step{
		fsAppSetup(world, func(settings *sidecartest.BridgeNetAppHostSettings) {
			settings.Forwarder = func(settings *sidecar.ForwarderSettings) {
				settings.CompileHeapCeilingByteCount = fsAppHeapCeilingByteCount
			}
		}, "subject", "second"),
		fsBridgeDo("subjects", world, func() error {
			for _, name := range []string{"subject", "second"} {
				forwarding, err := fsAppForward(world, name, "app no compile "+name)
				if err != nil {
					return err
				}
				forwardings[name] = forwarding
			}
			var err error
			*conn, err = fsAppConnect(world, fsForwardingWindow(world, "app no compile", world.subjects["subject"], forwardings["subject"], nil, nil), "uninterrupted;")
			if err != nil {
				return err
			}
			admission := world.world.Admission()
			*late = admission.Device("bridge admin's late device", admission.Owner().MemberId)
			admission.AdmitDevice(admission.Owner(), *late, 0)
			world.world.Follow()
			block()
			return nil
		}),
	}
}

// The overdue condition as the Forwarder's status reads it: the posture enforcing, never pending, Overdue naming
// n, and narrowing_overdue standing.
func fsAppOverdueStands(world *fsBridgeWorld, n uint64) error {
	status := world.host.Forwarder().Status()
	if status.Decision.State != sidecar.BridgeSinkEnforcing || status.Decision.Overdue == nil || status.Decision.Overdue.N != n {
		return fmt.Errorf("the status does not show the overdue condition at %d: %+v", n, status.Decision)
	}
	if !slices.ContainsFunc(status.Alarms, func(alarm sidecar.BridgeAlarm) bool {
		return alarm.Reason == sidecar.SidecarBridgeAlarm(sidecar.ForwarderAlarmNarrowingOverdue)
	}) {
		return fmt.Errorf("narrowing_overdue does not stand: %+v", status.Alarms)
	}
	if decision := world.host.Bridge.Decision(); !decision.State.Enforcing() {
		return fmt.Errorf("the posture is %s under an overdue entry", decision.State)
	}
	if overdue := world.host.Bridge.Status().Overdue; overdue == nil || overdue.N != n {
		return fmt.Errorf("the device role's status does not show the condition at %d: %+v", n, overdue)
	}
	return nil
}

// Checks the narrowing_overdue raises: at the times, positions and ages given, in order, and no other.
func fsAppOverdueRaises(world *fsBridgeWorld, firstSeen time.Time, want [][3]any) error {
	raised := world.host.WaitForwarderAlarms(sidecar.ForwarderAlarmNarrowingOverdue, len(want))
	if len(raised) != len(want) {
		return fmt.Errorf("narrowing_overdue raised %d times, not %d: %+v", len(raised), len(want), raised)
	}
	for i, alarm := range raised {
		at, n, age := want[i][0].(time.Duration), want[i][1].(uint64), want[i][2].(time.Duration)
		if !alarm.At.Equal(firstSeen.Add(at)) || alarm.N != n || alarm.Age != age {
			return fmt.Errorf("raise %d at %s naming %d at %s, not at %s naming %d at %s", i, alarm.At.Sub(firstSeen), alarm.N, alarm.Age, at, n, age)
		}
	}
	return nil
}

// The posture's first sight of the waiting entry at n.
func fsAppFirstSeen(world *fsBridgeWorld, n uint64) (time.Time, error) {
	for _, waiting := range world.host.Bridge.Decision().Waiting {
		if waiting.N <= n && n <= waiting.ThroughN {
			return waiting.FirstSeen, nil
		}
	}
	return time.Time{}, fmt.Errorf("the posture holds no waiting entry at %d: %+v", n, world.host.Bridge.Decision().Waiting)
}

// The uncheckable revocation's steps, which the no-compile schedules share: the late device's DelegationRevoke of the
// subject's forwarding Delegation waits, the key admitted and its connection carrying on; narrowing_overdue at 10 min
// naming it; a second uncheckable entry, first seen at 15 min, raised at once at its own 10 min; the repeat at 30; the
// condition standing throughout. Each raise is recorded at the clock's time and carries the posture's own.
func fsAppOverdueSteps(world *fsBridgeWorld, forwardings map[string]*sidecartest.BridgeNetForwarding, conn *fsAppConn,
	late **sidecartest.AdmissionDevice, revokedAt *uint64,
) []*Step {
	var firstSeen time.Time
	return []*Step{
		fsBridgeDo("admin", world, func() error {
			admission := world.world.Admission()
			*revokedAt = world.world.Land(*late, bridge.SignedType_SIGNED_DELEGATION_REVOKE, admission.DelegationRevoke(forwardings["subject"].DelegationId, 0))
			world.host.WaitApplied(*revokedAt)
			var err error
			if firstSeen, err = fsAppFirstSeen(world, *revokedAt); err != nil {
				return err
			}
			if err := fsAppCarries(world, *conn, "uninterrupted;", "waiting;"); err != nil {
				return err
			}
			window := fsForwardingWindow(world, "app no compile waiting", world.subjects["subject"], forwardings["subject"], nil, nil)
			defer window.Close()
			return (&fsBridgeFlows{world: world, window: window}).expectOpen("app no compile waiting")
		}),
		fsBridgeDo("clock", world, func() error {
			fsAppAdvanceTo(world, firstSeen.Add(10*time.Minute-time.Second))
			if alarms := world.host.ForwarderAlarms(); slices.ContainsFunc(alarms, func(alarm sidecartest.BridgeNetForwarderAlarm) bool {
				return alarm.Reason == sidecar.ForwarderAlarmNarrowingOverdue
			}) {
				return fmt.Errorf("narrowing_overdue before 10 min: %+v", alarms)
			}
			fsAppAdvanceTo(world, firstSeen.Add(10*time.Minute))
			if err := fsAppOverdueRaises(world, firstSeen, [][3]any{{10 * time.Minute, *revokedAt, 10 * time.Minute}}); err != nil {
				return err
			}
			if err := fsAppOverdueStands(world, *revokedAt); err != nil {
				return err
			}
			// the accepted trace (FwdReach-NoCompile): past its deadline the revoked key is still admitted
			window := fsForwardingWindow(world, "app no compile overdue", world.subjects["subject"], forwardings["subject"], nil, nil)
			defer window.Close()
			if err := (&fsBridgeFlows{world: world, window: window}).expectOpen("app no compile overdue"); err != nil {
				return fmt.Errorf("the key past its revocation's deadline: %w", err)
			}
			return fsAppCarries(world, *conn, "uninterrupted;", "overdue;")
		}),
		fsBridgeDo("admin", world, func() error {
			fsAppAdvanceTo(world, firstSeen.Add(15*time.Minute))
			admission := world.world.Admission()
			secondAt := world.world.Land(*late, bridge.SignedType_SIGNED_DELEGATION_REVOKE, admission.DelegationRevoke(forwardings["second"].DelegationId, 0))
			world.host.WaitApplied(secondAt)
			secondSeen, err := fsAppFirstSeen(world, secondAt)
			if err != nil {
				return err
			}
			// the landing moved api's clock a second past 15 min; its own point is 10 min after its first sight
			fsAppAdvanceTo(world, secondSeen.Add(10*time.Minute-time.Second))
			if err := fsAppOverdueRaises(world, firstSeen, [][3]any{{10 * time.Minute, *revokedAt, 10 * time.Minute}}); err != nil {
				return err
			}
			fsAppAdvanceTo(world, secondSeen.Add(10*time.Minute))
			ownAt := secondSeen.Add(10 * time.Minute).Sub(firstSeen)
			if err := fsAppOverdueRaises(world, firstSeen, [][3]any{
				{10 * time.Minute, *revokedAt, 10 * time.Minute},
				{ownAt, secondAt, 10 * time.Minute},
			}); err != nil {
				return fmt.Errorf("a further overdue entry waited for a repeat (RepeatsOnly): %w", err)
			}
			// the condition names the oldest throughout
			if err := fsAppOverdueStands(world, *revokedAt); err != nil {
				return err
			}
			fsAppAdvanceTo(world, firstSeen.Add(30*time.Minute))
			if err := fsAppOverdueRaises(world, firstSeen, [][3]any{
				{10 * time.Minute, *revokedAt, 10 * time.Minute},
				{ownAt, secondAt, 10 * time.Minute},
				{30 * time.Minute, *revokedAt, 30 * time.Minute},
			}); err != nil {
				return err
			}
			if err := fsAppOverdueStands(world, *revokedAt); err != nil {
				return err
			}
			return fsAppCarries(world, *conn, "uninterrupted;", "at 30 min;")
		}),
	}
}

// FwdReach-NoCompile on real code (QD-621, QD-696): compiles deferred by the heap, as under sustained provider load,
// an uncheckable revocation leaves the state in force and the key admitted while narrowing_overdue is raised at 10
// min, at once for a second entry when it becomes overdue, and again at 30; the first compile let run applies the
// revocation, ends the key's connection and clears the condition.
func FwdAppNoCompileOverdue(net *Net) *Schedule {
	world := newFsBridgeWorld()
	forwardings := map[string]*sidecartest.BridgeNetForwarding{}
	var conn fsAppConn
	var late *sidecartest.AdmissionDevice
	var revokedAt uint64
	steps := fsAppNoCompileSteps(world, forwardings, &conn, &late, func() {
		world.host.SetHeapInUse(fsAppHeapCeilingByteCount)
	})
	steps = append(steps, fsAppOverdueSteps(world, forwardings, &conn, &late, &revokedAt)...)
	steps = append(steps, fsBridgeDo("host", world, func() error {
		defer conn.Close()
		if !slices.ContainsFunc(world.host.ForwarderAlarms(), func(alarm sidecartest.BridgeNetForwarderAlarm) bool {
			return alarm.Reason == sidecar.ForwarderAlarmCompileDeferred
		}) {
			return fmt.Errorf("compiles deferred for 30 min raised no compile_deferred: %+v", world.host.ForwarderAlarms())
		}
		world.host.SetHeapInUse(0)
		// the deferred compile's next retry is at most its longest interval away
		clock := world.world.Net().Clock()
		fsAppAdvanceTo(world, clock.Now().Add(sidecar.DefaultForwarderSettings(sidecar.ForwarderHostApple).CompileRetryMaxInterval))
		world.host.WaitAdopted(world.world.Admission().Tip().GetVersion())
		if err := fsAppClosed(world, "uninterrupted;"); err != nil {
			return fmt.Errorf("the first compile let run: %w", err)
		}
		if status := world.host.Forwarder().Status(); status.Decision.Overdue != nil || slices.ContainsFunc(status.Alarms, func(alarm sidecar.BridgeAlarm) bool {
			return alarm.Reason == sidecar.SidecarBridgeAlarm(sidecar.ForwarderAlarmNarrowingOverdue)
		}) {
			return fmt.Errorf("the compile that judged the waiting entries left the condition: %+v", status)
		}
		for _, name := range []string{"subject", "second"} {
			window := fsForwardingWindow(world, "app no compile judged "+name, world.subjects[name], forwardings[name], nil, nil)
			err := fsAppRefused(world, window)
			window.Close()
			if err != nil {
				return fmt.Errorf("%s's revoked key after the compile: %w", name, err)
			}
		}
		return nil
	}))
	return fsAppSchedule("the first compile let run applies a revocation the posture could not check", world, steps...)
}

// The same over the memory cap (DESIGN-DETAILS 4.6; QD-621): the Forwarder restarted under a cap no compile fits,
// every compile refused with compile_over_budget, the posture enforcing and never pending while the uncheckable
// revocation waits, raised at 10, at once for the second and at 30, and the key admitted throughout, since no compile
// ever runs on this device until the review phase's storage-backed compile.
func FwdAppOverCapNeverPending(net *Net) *Schedule {
	world := newFsBridgeWorld()
	forwardings := map[string]*sidecartest.BridgeNetForwarding{}
	var conn fsAppConn
	var late *sidecartest.AdmissionDevice
	var revokedAt uint64
	steps := fsAppNoCompileSteps(world, forwardings, &conn, &late, func() {
		world.host.RestartForwarder(&sidecartest.BridgeNetForwarderRestart{Forwarder: func(settings *sidecar.ForwarderSettings) {
			settings.CompileMemoryMaxByteCount = 1
		}})
	})
	steps = append(steps, fsAppOverdueSteps(world, forwardings, &conn, &late, &revokedAt)...)
	steps = append(steps, fsBridgeDo("host", world, func() error {
		defer conn.Close()
		status := world.host.Forwarder().Status()
		if status.CompileCount != 0 || status.Admission != sidecar.ForwarderCompileOverBudget || 0 == status.CompileRefusedCount {
			return fmt.Errorf("a compile ran over the cap: %+v", status)
		}
		if !slices.ContainsFunc(world.host.ForwarderAlarms(), func(alarm sidecartest.BridgeNetForwarderAlarm) bool {
			return alarm.Reason == sidecar.ForwarderAlarmCompileOverBudget
		}) {
			return fmt.Errorf("no compile_over_budget: %+v", world.host.ForwarderAlarms())
		}
		window := fsForwardingWindow(world, "app over cap", world.subjects["subject"], forwardings["subject"], nil, nil)
		defer window.Close()
		if err := (&fsBridgeFlows{world: world, window: window}).expectOpen("app over cap"); err != nil {
			return fmt.Errorf("the key over the cap: %w", err)
		}
		return fsAppOverdueStands(world, revokedAt)
	}))
	return fsAppSchedule("", world, steps...)
}

// The steps the rollback schedule and its twin share: the subject's forwarding key and identity key admitted, and a
// copy of the posture's store taken while the key is live; then the subject's DelegationRevoke lands and is compiled,
// raising the floor past the copy; the host is closed.
func fsAppRollbackSteps(world *fsBridgeWorld, forwarding **sidecartest.BridgeNetForwarding, snapshot *map[string][]byte, revokedAt *uint64) []*Step {
	return []*Step{
		fsAppSetup(world, nil, "subject"),
		fsBridgeDo("subject", world, func() error {
			var err error
			if *forwarding, err = fsAppForward(world, "subject", "app rollback"); err != nil {
				return err
			}
			*snapshot = world.host.PostureStore().Snapshot()
			*revokedAt = world.world.RevokeForwarding(world.subjects["subject"], *forwarding)
			world.host.WaitApplied(*revokedAt)
			if floor := world.host.PostureFloor().N(); floor < *revokedAt {
				return fmt.Errorf("the floor stands at %d after the revocation at %d", floor, *revokedAt)
			}
			world.host.Close()
			return nil
		}),
	}
}

// Fwd.tla's NoFloor on real code: the posture's store put back to a copy from before the revocation, the restarted
// host is pending with store_rolled_back, its posture below the floor, and opens nothing for the revoked key or the
// identity key, until its Forwarder's compile brings the pin back to the floor; then only the identity key opens.
func FwdAppRollbackIsPending(net *Net) *Schedule {
	world := newFsBridgeWorld()
	var forwarding *sidecartest.BridgeNetForwarding
	var snapshot map[string][]byte
	var revokedAt uint64
	steps := fsAppRollbackSteps(world, &forwarding, &snapshot, &revokedAt)
	steps = append(steps, fsBridgeDo("attacker", world, func() error {
		world.host.PostureStore().Restore(snapshot)
		fsAppRestartHeld(world)
		decision := world.host.Bridge.Decision()
		if decision.State != device.PosturePending || !slices.ContainsFunc(decision.Alarms, func(alarm device.PostureAlarm) bool {
			return alarm.Kind == device.PostureAlarmStoreRolledBack
		}) {
			return fmt.Errorf("a store below the floor restored as %s: %+v", decision.State, decision.Alarms)
		}
		for name, window := range map[string]*sidecartest.BridgeNetWindow{
			"the revoked key":  fsForwardingWindow(world, "app rollback forwarding", world.subjects["subject"], forwarding, nil, nil),
			"the identity key": world.world.OpenWindow("app rollback identity", world.subjects["subject"], world.host, nil),
		} {
			err := fsAppRefused(world, window)
			window.Close()
			if err != nil {
				return fmt.Errorf("%s under a rolled-back store: %w", name, err)
			}
		}
		world.host.ReleaseCompiles()
		world.host.WaitAdopted(world.world.Admission().Tip().GetVersion())
		revoked := fsForwardingWindow(world, "app rollback revoked", world.subjects["subject"], forwarding, nil, nil)
		defer revoked.Close()
		if err := fsAppRefused(world, revoked); err != nil {
			return fmt.Errorf("the revoked key once the pin is back: %w", err)
		}
		conn, err := fsAppConnect(world, world.world.OpenWindow("app rollback identity after", world.subjects["subject"], world.host, nil), "identity after rollback;")
		if err != nil {
			return err
		}
		return conn.Close()
	}))
	return fsAppSchedule("a posture store put back below the floor is pending until the pin is back", world, steps...)
}

// The rollback schedule's twin: the same restart over the store as the revocation left it is enforcing at once, before
// any compile, refusing the revoked key and opening the identity key's window.
func FwdAppRestartKeepsTheState(net *Net) *Schedule {
	world := newFsBridgeWorld()
	var forwarding *sidecartest.BridgeNetForwarding
	var snapshot map[string][]byte
	var revokedAt uint64
	steps := fsAppRollbackSteps(world, &forwarding, &snapshot, &revokedAt)
	steps = append(steps, fsBridgeDo("host", world, func() error {
		fsAppRestartHeld(world)
		defer world.host.ReleaseCompiles()
		if decision := world.host.Bridge.Decision(); !decision.State.Enforcing() || decision.Pin.GetVersion() < revokedAt {
			return fmt.Errorf("the restart with no rollback restored %s at %d", decision.State, decision.Pin.GetVersion())
		}
		revoked := fsForwardingWindow(world, "app restart revoked", world.subjects["subject"], forwarding, nil, nil)
		err := fsAppRefused(world, revoked)
		revoked.Close()
		if err != nil {
			return fmt.Errorf("the revoked key after a restart: %w", err)
		}
		conn, err := fsAppConnect(world, world.world.OpenWindow("app restart identity", world.subjects["subject"], world.host, nil), "identity after restart;")
		if err != nil {
			return err
		}
		return conn.Close()
	}))
	return fsAppSchedule("", world, steps...)
}

// A restarted app host over the old one's posture, Forwarder store, keys and upstream, every compile held at its
// admission from the start, so what the restored posture holds is what the host enforces until the schedule lets a
// compile run.
func fsAppRestartHeld(world *fsBridgeWorld) {
	old := world.host
	world.host = world.world.StartAppHost(old.Device, &sidecartest.BridgeNetAppHostSettings{Restart: old, NoWait: true, HoldCompiles: true})
}
