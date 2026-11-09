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

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html"
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
	// Task Scheduler's folder and task prefix
	unitTaskPrefix = `URnetwork\ur-`
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
	// Run in order after the file is written. A failure stops the install.
	install [][]string
	// Before the install, run with failures ignored, so an install over an install replaces it.
	reset [][]string
	// Run in order to remove it, failures ignored where the unit may not be there, then the file goes.
	uninstall [][]string
	// After the file goes.
	afterUninstall [][]string
}

// The unit of instance on env's OS, running executable. Refuses an instance name that is not one, and an executable
// path a unit could not quote.
func unitPlanFor(env *unitEnv, instance string, executable string) (*unitPlan, error) {
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
			content:        launchAgentPlist(label, executable, instance),
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
		plan := &unitPlan{
			path:           filepath.Join(configHome, "systemd", "user", unit+".service"),
			content:        systemdUserUnit(executable, instance),
			install:        [][]string{{"systemctl", "--user", "daemon-reload"}, {"systemctl", "--user", "enable", "--now", unit}},
			uninstall:      [][]string{{"systemctl", "--user", "disable", "--now", unit}},
			afterUninstall: [][]string{{"systemctl", "--user", "daemon-reload"}},
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

// The LaunchAgent: the daemon at load, kept alive, as the user, ur by its absolute path.
func launchAgentPlist(label string, executable string, instance string) []byte {
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
</dict>
</plist>
`)
	return plist.Bytes()
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

// Installs the unit: writes its file when its content differs, then runs its reset and install, so a second install
// changes nothing.
func installDaemonUnit(ctx context.Context, env *unitEnv, runner unitRunner, instance string, executable string) error {
	plan, err := unitPlanFor(env, instance, executable)
	if err != nil {
		return err
	}
	if plan.path != "" {
		existing, err := os.ReadFile(plan.path)
		if err != nil || !bytes.Equal(existing, plan.content) {
			if err := os.MkdirAll(filepath.Dir(plan.path), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(plan.path, plan.content, 0o644); err != nil {
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
	plan, err := unitPlanFor(env, instance, executable)
	if err != nil {
		return err
	}
	for _, command := range plan.uninstall {
		runner(ctx, command[0], command[1:]...)
	}
	if plan.path != "" {
		if err := os.Remove(plan.path); err != nil && !errors.Is(err, os.ErrNotExist) {
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
