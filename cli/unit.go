// §5.8's units: install-daemon runs the instance's daemon as the user (Q-CORE-3) from its OS's own service manager,
// so it starts at the user's login, or at boot under linger, and never idles out: a LaunchAgent network.ur.ur.<i> on
// macOS, systemd's user unit ur@<i> on Linux, with linger on a headless host, and a Task Scheduler logon task on
// Windows. Each runs ur by its absolute path, since a host a GUI launched lacks the shell's PATH (§4.10), with
// --unit, which keeps idle exit off. uninstall-daemon stops and removes the unit; retiring the device's indexer
// designations arrives with CORE-M2-09, and --purge's SidecarRevoke with CORE-M2-07.
//
// What a unit is and what installing and removing it runs are written here for every OS, so each OS's golden file
// and command list is tested on any host; unit_<os>.go gives the host's own environment. Both are idempotent: an
// install over an install changes nothing, and an uninstall of nothing succeeds.
//
// While a gateway grant stands (DESIGN-COMPUTE §8.4, D-GW-3, GW-M12-01) the unit also holds the gateway's port, where
// the OS holds a socket for a unit, so no other user's process takes the port across the daemon's restarts: launchd's
// Sockets in the LaunchAgent, one name with the port's two loopback addresses, which the daemon checks in by
// launch_activate_socket (unit_darwin.go); a systemd user socket unit ur@<i>.socket beside the service, whose two
// ListenStream sockets the service inherits by name (sd_listen_fds' protocol, unit_linux.go). The daemon takes each
// socket for the address it is bound to and nothing else (sidecar's gateway_listener.go). Windows' logon task holds no
// socket, so there the daemon binds the port itself at its start. An uninstall takes the socket unit away whatever it
// held.

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/urnetwork/sidecar"
)

// The format values a unit names.
const (
	// macOS's LaunchAgent label prefix (§5.8): network.ur.ur.<instance>
	unitLaunchAgentPrefix = "network.ur.ur."
	// systemd's user unit, ur@<instance>
	unitSystemdPrefix = "ur@"
	// systemd's unit suffixes: the service, and the socket unit that holds the gateway's port beside it
	unitSystemdServiceSuffix = ".service"
	unitSystemdSocketSuffix  = ".socket"
	// Task Scheduler's folder and task prefix
	unitTaskPrefix = `URnetwork\ur-`
	// the name the gateway's sockets go by: launchd's Sockets key, and systemd's FileDescriptorName
	unitGatewaySocketName = "gateway"
)

// Where and as whom a unit is installed.
type unitEnv struct {
	goos string
	// the user's home, under which macOS's LaunchAgents and the default systemd user directory live
	home string
	// $XDG_CONFIG_HOME on Linux, empty for ~/.config
	xdgConfigHome string
	// the user's uid, which names macOS's gui domain
	uid int
	// a Linux host with no graphical session, which needs linger to start the unit at boot
	headless bool
}

// Runs one command of a unit's install or removal, its output to the person's stderr.
type unitRunner func(ctx context.Context, name string, args ...string) error

// What installing a unit writes and runs, and what removing it runs.
type unitPlan struct {
	// The unit's file, empty on Windows, where the task is the unit.
	path    string
	content []byte
	// systemd's socket unit, which holds the gateway's port: written where a grant stands, empty otherwise.
	socketPath    string
	socketContent []byte
	// Files an uninstall removes beside path, whether or not this install wrote them: systemd's socket unit.
	removePaths []string
	// Run in order after the file is written. A failure stops the install.
	install [][]string
	// Before the install, run with failures ignored, so an install over an install replaces it.
	reset [][]string
	// Run in order to remove it, failures ignored where the unit may not be there, then the file goes.
	uninstall [][]string
	// After the file goes.
	afterUninstall [][]string
}

// The unit of instance on env's OS, running executable, holding the gateway's port where gatewayPort is one (0 for
// none). Refuses an instance name that is not one, and an executable path a unit could not quote.
func unitPlanFor(env *unitEnv, instance string, executable string, gatewayPort int) (*unitPlan, error) {
	if gatewayPort < 0 || 65535 < gatewayPort {
		return nil, fmt.Errorf("%d is not a port", gatewayPort)
	}
	if _, err := sidecar.SidecarInstanceName(instance); err != nil || instance == "" {
		return nil, fmt.Errorf("%q is not an instance name", instance)
	}
	if !filepath.IsAbs(executable) && !(env.goos == "windows" && isWindowsAbsolute(executable)) {
		return nil, errors.New("a unit runs ur by an absolute path")
	}
	if strings.ContainsAny(executable, "\"\n\r\t%\x00") {
		return nil, errors.New("ur's path holds a character a unit cannot quote")
	}
	switch env.goos {
	case "darwin":
		if env.home == "" {
			return nil, errors.New("no home directory for the LaunchAgent")
		}
		label := unitLaunchAgentPrefix + instance
		domain := "gui/" + strconv.Itoa(env.uid)
		path := filepath.Join(env.home, "Library", "LaunchAgents", label+".plist")
		return &unitPlan{
			path:           path,
			content:        launchAgentPlist(label, executable, instance, gatewayPort),
			reset:          [][]string{{"launchctl", "bootout", domain + "/" + label}},
			install:        [][]string{{"launchctl", "bootstrap", domain, path}},
			uninstall:      [][]string{{"launchctl", "bootout", domain + "/" + label}},
			afterUninstall: nil,
		}, nil
	case "linux":
		configHome := env.xdgConfigHome
		if configHome == "" {
			if env.home == "" {
				return nil, errors.New("no home directory for the systemd user unit")
			}
			configHome = filepath.Join(env.home, ".config")
		}
		unit := unitSystemdPrefix + instance
		socketUnit := unit + unitSystemdSocketSuffix
		socketPath := filepath.Join(configHome, "systemd", "user", socketUnit)
		plan := &unitPlan{
			path:           filepath.Join(configHome, "systemd", "user", unit+unitSystemdServiceSuffix),
			content:        systemdUserUnit(executable, instance),
			install:        [][]string{{"systemctl", "--user", "daemon-reload"}, {"systemctl", "--user", "enable", "--now", unit}},
			removePaths:    []string{socketPath},
			uninstall:      [][]string{{"systemctl", "--user", "disable", "--now", socketUnit}, {"systemctl", "--user", "disable", "--now", unit}},
			afterUninstall: [][]string{{"systemctl", "--user", "daemon-reload"}},
		}
		if 0 < gatewayPort {
			// the socket first, so the service, started again after it, inherits its sockets by name
			plan.socketPath, plan.socketContent = socketPath, systemdGatewaySocketUnit(instance, gatewayPort)
			plan.install = [][]string{
				{"systemctl", "--user", "daemon-reload"},
				{"systemctl", "--user", "enable", "--now", socketUnit},
				{"systemctl", "--user", "enable", unit},
				{"systemctl", "--user", "restart", unit},
			}
		}
		if env.headless {
			// a headless host has no login session to start user units at boot without it (§5.8)
			plan.install = append(plan.install, []string{"loginctl", "enable-linger"})
		}
		return plan, nil
	case "windows":
		task := unitTaskPrefix + instance
		return &unitPlan{
			install: [][]string{
				{"schtasks", "/Create", "/F", "/TN", task, "/SC", "ONLOGON", "/RL", "LIMITED", "/TR", windowsTaskCommand(executable, instance)},
				{"schtasks", "/Run", "/TN", task},
			},
			uninstall: [][]string{{"schtasks", "/End", "/TN", task}, {"schtasks", "/Delete", "/F", "/TN", task}},
		}, nil
	}
	return nil, fmt.Errorf("no daemon unit on %s", env.goos)
}

// Whether path is absolute on Windows, which filepath on another OS cannot say.
func isWindowsAbsolute(path string) bool {
	return 3 <= len(path) && path[1] == ':' && (path[2] == '\\' || path[2] == '/')
}

// The LaunchAgent: the daemon at load, kept alive, as the user, ur by its absolute path; with a gateway port, launchd's
// Sockets holding it on both loopback addresses under one name, which the daemon checks in.
func launchAgentPlist(label string, executable string, instance string, gatewayPort int) []byte {
	var plist bytes.Buffer
	plist.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + html.EscapeString(label) + `</string>
	<key>ProgramArguments</key>
	<array>
`)
	for _, argument := range unitDaemonArguments(executable, instance) {
		plist.WriteString("\t\t<string>" + html.EscapeString(argument) + "</string>\n")
	}
	plist.WriteString(`	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ProcessType</key>
	<string>Background</string>
`)
	if 0 < gatewayPort {
		plist.WriteString(`	<key>Sockets</key>
	<dict>
		<key>` + unitGatewaySocketName + `</key>
		<array>
`)
		for _, socket := range []struct {
			family string
			node   string
		}{{family: "IPv4", node: "127.0.0.1"}, {family: "IPv6", node: "::1"}} {
			plist.WriteString(`			<dict>
				<key>SockFamily</key>
				<string>` + socket.family + `</string>
				<key>SockNodeName</key>
				<string>` + socket.node + `</string>
				<key>SockServiceName</key>
				<string>` + strconv.Itoa(gatewayPort) + `</string>
				<key>SockType</key>
				<string>stream</string>
			</dict>
`)
		}
		plist.WriteString(`		</array>
	</dict>
`)
	}
	plist.WriteString(`</dict>
</plist>
`)
	return plist.Bytes()
}

// The systemd socket unit that holds the gateway's port beside ur@<instance>.service, which inherits its two sockets,
// both named gateway, by sharing its name. ipv6-only keeps [::1]'s socket off IPv4.
func systemdGatewaySocketUnit(instance string, gatewayPort int) []byte {
	port := strconv.Itoa(gatewayPort)
	return []byte(`[Unit]
Description=URnetwork sidecar gateway port, instance ` + instance + `

[Socket]
ListenStream=127.0.0.1:` + port + `
ListenStream=[::1]:` + port + `
BindIPv6Only=ipv6-only
FileDescriptorName=` + unitGatewaySocketName + `

[Install]
WantedBy=sockets.target
`)
}

// The systemd user unit: the daemon, restarted on failure, as the user.
func systemdUserUnit(executable string, instance string) []byte {
	quoted := []string{}
	for _, argument := range unitDaemonArguments(executable, instance) {
		quoted = append(quoted, `"`+argument+`"`)
	}
	return []byte(`[Unit]
Description=URnetwork sidecar daemon, instance ` + instance + `

[Service]
Type=simple
ExecStart=` + strings.Join(quoted, " ") + `
Restart=on-failure

[Install]
WantedBy=default.target
`)
}

// The logon task's command line, ur's path quoted.
func windowsTaskCommand(executable string, instance string) string {
	arguments := unitDaemonArguments(executable, instance)
	return `"` + arguments[0] + `" ` + strings.Join(arguments[1:], " ")
}

// What every unit runs: ur daemon of the instance, unit-run, so it never idles out.
func unitDaemonArguments(executable string, instance string) []string {
	return []string{executable, "daemon", "--instance", instance, "--unit"}
}

// Installs the unit, holding the gateway's port where gatewayPort is one: writes its files when their content
// differs, takes away a socket unit an earlier install wrote when none is held now, then runs its reset and install,
// so a second install changes nothing.
func installDaemonUnit(ctx context.Context, env *unitEnv, runner unitRunner, instance string, executable string, gatewayPort int) error {
	plan, err := unitPlanFor(env, instance, executable, gatewayPort)
	if err != nil {
		return err
	}
	write := func(path string, content []byte) error {
		existing, err := os.ReadFile(path)
		if err == nil && bytes.Equal(existing, content) {
			return nil
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		return os.WriteFile(path, content, 0o644)
	}
	if plan.path != "" {
		if err := write(plan.path, plan.content); err != nil {
			return err
		}
	}
	if plan.socketPath != "" {
		if err := write(plan.socketPath, plan.socketContent); err != nil {
			return err
		}
	} else {
		for _, path := range plan.removePaths {
			if err := os.Remove(path); err == nil {
				// a socket unit no grant needs any more: stopped, so the service it fed no longer takes its sockets
				runner(ctx, "systemctl", "--user", "disable", "--now", filepath.Base(path))
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	for _, command := range plan.reset {
		runner(ctx, command[0], command[1:]...)
	}
	for _, command := range plan.install {
		if err := runner(ctx, command[0], command[1:]...); err != nil {
			return fmt.Errorf("%s: %w", command[0], err)
		}
	}
	return nil
}

// Stops and removes the unit, and succeeds when there is none. A command's failure is ignored, since the unit may
// already be stopped or gone; the file's removal is not.
func uninstallDaemonUnit(ctx context.Context, env *unitEnv, runner unitRunner, instance string, executable string) error {
	plan, err := unitPlanFor(env, instance, executable, 0)
	if err != nil {
		return err
	}
	for _, command := range plan.uninstall {
		runner(ctx, command[0], command[1:]...)
	}
	for _, path := range append([]string{plan.path}, plan.removePaths...) {
		if path == "" {
			continue
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	for _, command := range plan.afterUninstall {
		runner(ctx, command[0], command[1:]...)
	}
	return nil
}

// Runs a command for real, its output to stderr, never stdout.
func execUnitRunner(cli *urCli) unitRunner {
	return func(ctx context.Context, name string, args ...string) error {
		command := exec.CommandContext(ctx, name, args...)
		command.Stdout = cli.stderr
		command.Stderr = cli.stderr
		return command.Run()
	}
}

// sd_listen_fds' protocol, the variables systemd passes a service its sockets by, and the first descriptor it passes.
const (
	unitListenPidVariable     = "LISTEN_PID"
	unitListenFdsVariable     = "LISTEN_FDS"
	unitListenFdNamesVariable = "LISTEN_FDNAMES"
	unitListenFdsStart        = 3
)

// The gateway's sockets systemd passed this process, by sd_listen_fds' protocol: LISTEN_PID naming pid, LISTEN_FDS
// descriptors from 3, LISTEN_FDNAMES their names, colon-separated; each named gateway is made a listener, its descriptor
// closed once the listener holds its own copy, and every other descriptor passed is left as it is but marked to close
// on exec, so no child inherits it. None where the variables name another process or none. file makes the *os.File of
// a descriptor, os.NewFile unless a test stands one in; closeOnExec marks one, which a test may leave alone.
func systemdGatewayListeners(getenv func(name string) string, pid int, file func(fd uintptr, name string) *os.File,
	closeOnExec func(fd int)) ([]net.Listener, error) {
	listenPid, err := strconv.Atoi(getenv(unitListenPidVariable))
	if err != nil || listenPid != pid {
		return nil, nil
	}
	count, err := strconv.Atoi(getenv(unitListenFdsVariable))
	if err != nil || count <= 0 {
		return nil, nil
	}
	names := strings.Split(getenv(unitListenFdNamesVariable), ":")
	listeners := []net.Listener{}
	errs := []error{}
	for i := 0; i < count; i += 1 {
		fd := unitListenFdsStart + i
		if i >= len(names) || names[i] != unitGatewaySocketName {
			closeOnExec(fd)
			continue
		}
		passed := file(uintptr(fd), unitGatewaySocketName)
		if passed == nil {
			errs = append(errs, fmt.Errorf("descriptor %d does not open", fd))
			continue
		}
		listener, err := net.FileListener(passed)
		passed.Close()
		if err != nil {
			errs = append(errs, fmt.Errorf("descriptor %d does not listen: %w", fd, err))
			continue
		}
		listeners = append(listeners, listener)
	}
	return listeners, errors.Join(errs...)
}
