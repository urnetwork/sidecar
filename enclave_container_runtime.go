//go:build !ios_extension && !sidecar_http

// The containers' runtimes (DESIGN-COMPUTE §11.10, §11.14; D-ENC-13): what turns a plan into the commands that start a
// container and run a process in it, as data on every leg.
//
//	nspawn   the design's: systemd-run starts a scope of the plan's slice with its limits, and systemd-nspawn runs
//	         the container in it, its first process the seccomp shim, which installs the filter and execs systemd;
//	         an Exec runs ur outside under the shim's name, so the filter holds before nsenter enters the
//	         container's namespaces, in the scope's Exec leaf (CLONE_INTO_CGROUP)
//	runsc    gVisor's, over an OCI bundle of the same root, mounts, user namespace and filter, for D-ENC-13's
//	         evaluation alone: adopted only once apt, builds and the network tools pass under it (External). Its
//	         network is a namespace of its own with no veth until the evaluation wires one, its first process is
//	         not found the nspawn way and the container socket cannot bind its callers by ancestry, so under it a
//	         start ends at StartTimeout and every socket caller is refused: the closed side
//
// EnclaveContainerFiles renders the default plans as the files the image carries in enclave/container/: each
// container's nspawn settings, the seccomp profile and the kernel settings the boundary needs; TestEnclaveContainerFilesAreCurrent
// holds them to the code, so the image and the daemon cannot drift.

package sidecar

import (
	"encoding/json"
	"fmt"
	"path"
	"strconv"
	"strings"
)

// What turns a plan into commands. Safe for concurrent use.
type EnclaveContainerRuntime interface {
	// Its name, the settings' Runtime.
	Name() EnclaveContainerRuntimeName
	// Adds the runtime's own files to the plan, or refuses a plan it cannot run.
	Prepare(plan *EnclaveContainerPlan) error
	// The command that runs the container in the foreground until it ends.
	StartCommand(plan *EnclaveContainerPlan) (*EnclaveContainerCommand, error)
	// The command that runs spec inside the running container whose first process is leaderPid.
	ExecCommand(plan *EnclaveContainerPlan, leaderPid int, spec *EnclaveContainerExec) (*EnclaveContainerCommand, error)
}

// The runtime settings name.
func NewEnclaveContainerRuntime(settings *EnclaveContainerSettings) (EnclaveContainerRuntime, error) {
	switch settings.Runtime {
	case EnclaveContainerRuntimeNspawn:
		return &enclaveNspawnRuntime{settings: settings}, nil
	case EnclaveContainerRuntimeRunsc:
		return &enclaveRunscRuntime{settings: settings}, nil
	}
	return nil, fmt.Errorf("%w: the runtime %q", ErrEnclaveContainerSettings, settings.Runtime)
}

// The working directory an Exec runs in, checked.
func enclaveContainerExecDir(spec *EnclaveContainerExec) (string, error) {
	if spec.Dir == "" {
		return "/", nil
	}
	if !path.IsAbs(spec.Dir) || path.Clean(spec.Dir) != spec.Dir || strings.ContainsAny(spec.Dir, "\x00\n") {
		return "", fmt.Errorf("%w: the working directory is not absolute and clean", ErrEnclaveContainerRefused)
	}
	return spec.Dir, nil
}

// systemd-run's arguments that start a scope of the plan's with its limits, up to the "--" before the runtime.
func enclaveContainerScopeArgv(settings *EnclaveContainerSettings, plan *EnclaveContainerPlan) []string {
	argv := []string{
		settings.SystemdRunPath, "--scope", "--quiet", "--collect",
		"--unit=" + plan.ScopeName, "--slice=" + plan.SliceName,
	}
	for _, property := range plan.ScopeProperties {
		argv = append(argv, "--property="+property)
	}
	return append(argv, "--")
}

// systemd-nspawn, the design's runtime.
type enclaveNspawnRuntime struct {
	settings *EnclaveContainerSettings
}

// nspawn.
func (self *enclaveNspawnRuntime) Name() EnclaveContainerRuntimeName {
	return EnclaveContainerRuntimeNspawn
}

// nspawn needs nothing written beyond the plan's own files.
func (self *enclaveNspawnRuntime) Prepare(plan *EnclaveContainerPlan) error {
	return nil
}

// nspawn's arguments for the plan, past the binary's path: what TestEnclaveContainerPlan reads, and the nspawn
// settings file renders.
func (self *enclaveNspawnRuntime) nspawnArgs(plan *EnclaveContainerPlan) []string {
	args := []string{
		"--quiet",
		// the scope systemd-run made is the container's, with its limits
		"--keep-unit",
		"--register=no",
		// nothing in a file beside the root, which the scratch volume holds, may change what follows
		"--settings=no",
		"--machine=" + plan.MachineName,
		"--directory=" + plan.RootPath,
		fmt.Sprintf("--private-users=%d:%d", plan.UidBase, plan.UidCount),
		// the root's owners on disk map to the container's range through an idmapped mount, so the edit container
		// sees the agents' files owned as the agents do
		"--private-users-ownership=map",
		// its own network namespace, owned by its user namespace, joined to the host by a veth
		"--network-veth",
		"--resolv-conf=off",
		"--link-journal=no",
		"--console=passive",
		"--kill-signal=" + enclaveContainerKillSignal,
		fmt.Sprintf("--oom-score-adjust=%d", plan.OomScoreAdjust),
		"--system-call-filter=~" + strings.Join(plan.DeniedSystemCalls, " "),
	}
	for _, mount := range plan.Mounts {
		flag := "--bind="
		if mount.ReadOnly {
			flag = "--bind-ro="
		}
		spec := mount.Source + ":" + mount.Target
		if mount.Idmap {
			spec += ":idmap"
		}
		args = append(args, flag+spec)
	}
	for _, device := range plan.Devices {
		args = append(args, "--bind="+device)
	}
	return args
}

// systemd-run's scope around systemd-nspawn, whose first process is the shim and then the init.
func (self *enclaveNspawnRuntime) StartCommand(plan *EnclaveContainerPlan) (*EnclaveContainerCommand, error) {
	argv := enclaveContainerScopeArgv(self.settings, plan)
	argv = append(argv, self.settings.NspawnPath)
	argv = append(argv, self.nspawnArgs(plan)...)
	// nspawn runs what follows as the container's first process: the shim, then the init (enclave_container_linux.go)
	argv = append(argv, "--")
	argv = append(argv, plan.InitArgv...)
	return &EnclaveContainerCommand{Argv: argv, Env: []string{"PATH=" + self.settings.ExecSearchPath}}, nil
}

// ur outside under the shim's name, so the filter holds before nsenter enters the container; nsenter enters every
// namespace of the first process's, its root and the working directory there, as the user's ids there.
func (self *enclaveNspawnRuntime) ExecCommand(plan *EnclaveContainerPlan, leaderPid int, spec *EnclaveContainerExec) (*EnclaveContainerCommand, error) {
	if leaderPid <= 0 {
		return nil, ErrEnclaveContainerState
	}
	uid, gid, err := spec.ids()
	if err != nil {
		return nil, err
	}
	dir, err := enclaveContainerExecDir(spec)
	if err != nil {
		return nil, err
	}
	env, err := spec.environment(plan.ExecSearchPath)
	if err != nil {
		return nil, err
	}
	argv := []string{
		plan.UrPath, "--", plan.NsenterPath,
		"--target", strconv.Itoa(leaderPid),
		"--user", "--mount", "--pid", "--net", "--ipc", "--uts", "--cgroup",
		"--root", "--wd=" + dir,
		"--setuid", strconv.FormatUint(uint64(uid), 10), "--setgid", strconv.FormatUint(uint64(gid), 10),
		"--",
	}
	argv = append(argv, spec.Argv...)
	return &EnclaveContainerCommand{
		Argv:       argv,
		Name:       enclaveSeccompShimName,
		Env:        env,
		CgroupPath: plan.ExecCgroupPath,
		CgroupLeaf: true,
		Stdin:      spec.Stdin,
		Stdout:     spec.Stdout,
		Stderr:     spec.Stderr,
	}, nil
}

// gVisor's runsc over an OCI bundle, for D-ENC-13's evaluation.
type enclaveRunscRuntime struct {
	settings *EnclaveContainerSettings
}

// runsc.
func (self *enclaveRunscRuntime) Name() EnclaveContainerRuntimeName {
	return EnclaveContainerRuntimeRunsc
}

// The bundle's directory, beside the overlay.
func (self *enclaveRunscRuntime) bundlePath(plan *EnclaveContainerPlan) string {
	return path.Join(plan.StatePath, "bundle")
}

// Writes the bundle's config.json into the plan's files. A plan with devices is refused: M15's GPUs run under nspawn.
func (self *enclaveRunscRuntime) Prepare(plan *EnclaveContainerPlan) error {
	if 0 < len(plan.Devices) {
		return fmt.Errorf("%w: runsc takes no devices", ErrEnclaveContainerSettings)
	}
	config, err := self.ociConfig(plan)
	if err != nil {
		return err
	}
	plan.Files[path.Join(self.bundlePath(plan), "config.json")] = config
	return nil
}

// systemd-run's scope around runsc's run of the bundle, its filter applied inside the sandbox.
func (self *enclaveRunscRuntime) StartCommand(plan *EnclaveContainerPlan) (*EnclaveContainerCommand, error) {
	argv := enclaveContainerScopeArgv(self.settings, plan)
	argv = append(argv, self.settings.RunscPath, "--root="+self.settings.RunscStatePath, "--oci-seccomp",
		"run", "--bundle="+self.bundlePath(plan), plan.MachineName)
	return &EnclaveContainerCommand{Argv: argv, Env: []string{"PATH=" + self.settings.ExecSearchPath}}, nil
}

// runsc's exec into the sandbox, the user, directory and environment as flags.
func (self *enclaveRunscRuntime) ExecCommand(plan *EnclaveContainerPlan, leaderPid int, spec *EnclaveContainerExec) (*EnclaveContainerCommand, error) {
	uid, gid, err := spec.ids()
	if err != nil {
		return nil, err
	}
	dir, err := enclaveContainerExecDir(spec)
	if err != nil {
		return nil, err
	}
	env, err := spec.environment(plan.ExecSearchPath)
	if err != nil {
		return nil, err
	}
	argv := []string{self.settings.RunscPath, "--root=" + self.settings.RunscStatePath, "exec",
		fmt.Sprintf("--user=%d:%d", uid, gid), "--cwd=" + dir}
	for _, entry := range env {
		argv = append(argv, "--env="+entry)
	}
	argv = append(argv, plan.MachineName)
	argv = append(argv, spec.Argv...)
	return &EnclaveContainerCommand{
		Argv:   argv,
		Env:    []string{"PATH=" + self.settings.ExecSearchPath},
		Stdin:  spec.Stdin,
		Stdout: spec.Stdout,
		Stderr: spec.Stderr,
	}, nil
}

// The capabilities a container's root holds inside its user namespace: systemd-nspawn's default set and the
// network administration its private network grants, so runsc's root holds what nspawn's does.
var enclaveContainerCapabilities = []string{
	"CAP_AUDIT_CONTROL", "CAP_AUDIT_WRITE", "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER",
	"CAP_FSETID", "CAP_IPC_OWNER", "CAP_KILL", "CAP_LEASE", "CAP_LINUX_IMMUTABLE", "CAP_MKNOD", "CAP_NET_ADMIN",
	"CAP_NET_BIND_SERVICE", "CAP_NET_BROADCAST", "CAP_NET_RAW", "CAP_SETFCAP", "CAP_SETGID", "CAP_SETPCAP",
	"CAP_SETUID", "CAP_SYS_ADMIN", "CAP_SYS_BOOT", "CAP_SYS_CHROOT", "CAP_SYS_NICE", "CAP_SYS_PTRACE",
	"CAP_SYS_RESOURCE", "CAP_SYS_TTY_CONFIG",
}

// The OCI runtime spec's config.json for the plan: the same root, mounts, user namespace and filter as nspawn's.
func (self *enclaveRunscRuntime) ociConfig(plan *EnclaveContainerPlan) ([]byte, error) {
	seccomp, err := EnclaveContainerSeccompProfile().oci()
	if err != nil {
		return nil, err
	}
	type ociMount struct {
		Destination string   `json:"destination"`
		Type        string   `json:"type"`
		Source      string   `json:"source"`
		Options     []string `json:"options,omitempty"`
	}
	type ociIdMapping struct {
		ContainerId uint32 `json:"containerID"`
		HostId      uint32 `json:"hostID"`
		Size        uint32 `json:"size"`
	}
	mounts := []*ociMount{
		{Destination: "/proc", Type: "proc", Source: "proc"},
		{Destination: "/dev", Type: "tmpfs", Source: "tmpfs", Options: []string{"nosuid", "strictatime", "mode=755"}},
		{Destination: "/dev/pts", Type: "devpts", Source: "devpts", Options: []string{"nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620"}},
		{Destination: "/sys", Type: "sysfs", Source: "sysfs", Options: []string{"nosuid", "noexec", "nodev", "ro"}},
	}
	for _, mount := range plan.Mounts {
		options := []string{"rbind", "rw"}
		if mount.ReadOnly {
			options = []string{"rbind", "ro"}
		}
		if mount.Idmap {
			options = append(options, "idmap")
		}
		mounts = append(mounts, &ociMount{Destination: mount.Target, Type: "bind", Source: mount.Source, Options: options})
	}
	idMappings := []*ociIdMapping{{ContainerId: 0, HostId: plan.UidBase, Size: plan.UidCount}}
	config := map[string]any{
		"ociVersion": "1.0.2",
		"process": map[string]any{
			"terminal": false,
			"user":     map[string]any{"uid": 0, "gid": 0},
			"args":     plan.InitArgv[len(plan.InitArgv)-1:],
			"env":      []string{"PATH=" + plan.ExecSearchPath, "container=ur-runsc"},
			"cwd":      "/",
			"capabilities": map[string]any{
				"bounding": enclaveContainerCapabilities, "effective": enclaveContainerCapabilities,
				"permitted": enclaveContainerCapabilities,
			},
			"noNewPrivileges": false,
		},
		"root":     map[string]any{"path": plan.RootPath, "readonly": false},
		"hostname": plan.MachineName,
		"mounts":   mounts,
		"linux": map[string]any{
			"namespaces": []map[string]string{
				{"type": "pid"}, {"type": "network"}, {"type": "ipc"}, {"type": "uts"}, {"type": "mount"}, {"type": "user"},
			},
			"uidMappings": idMappings,
			"gidMappings": idMappings,
			"resources": map[string]any{
				"devices": []map[string]any{{"allow": false, "access": "rwm"}},
			},
			"seccomp":       seccomp,
			"maskedPaths":   []string{"/proc/kcore", "/proc/keys", "/proc/timer_list", "/sys/firmware", "/sys/kernel/config", "/sys/kernel/security"},
			"readonlyPaths": []string{"/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"},
		},
	}
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

// The file names enclave/container/ holds, beside the role files.
const (
	enclaveContainerFilesSeccomp = "seccomp.json"
	enclaveContainerFilesSysctl  = "90-ur-enclave-container.conf"
	enclaveContainerFilesNspawn  = ".nspawn"
)

// The files the image carries in enclave/container/, by name, rendered from settings: each container's nspawn
// settings (the static half of its plan, for review: the daemon passes the whole plan on nspawn's command line with
// --settings=no), the seccomp profile in OCI's form, and the kernel settings the boundary needs, which the image
// installs in /etc/sysctl.d and Start checks.
func EnclaveContainerFiles(settings *EnclaveContainerSettings) (map[string][]byte, error) {
	agents, err := NewEnclaveContainerPlan(settings, EnclaveContainerRoleAgents, "")
	if err != nil {
		return nil, err
	}
	edit, err := NewEnclaveContainerPlan(settings, EnclaveContainerRoleEdit, agents.RootPath)
	if err != nil {
		return nil, err
	}
	seccomp, err := EnclaveContainerSeccompProfile().OciJson()
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{
		enclaveContainerFilesSeccomp: seccomp,
		enclaveContainerFilesSysctl: []byte(strings.Join([]string{
			"# Generated from DefaultEnclaveContainerSettings by EnclaveContainerFiles (enclave_container_runtime.go);",
			"# TestEnclaveContainerFilesAreCurrent holds it. The kernel settings the agents' and edit containers'",
			"# boundary needs (DESIGN-COMPUTE §11.10), outside any container's reach: the image installs this file in",
			"# /etc/sysctl.d, and a container's start checks the first two before anything runs.",
			"kernel.unprivileged_bpf_disabled = 1",
			"kernel.io_uring_disabled = 2",
			"# Debian's: gdb and strace work inside a container; the boundary is the user namespace, not this.",
			"kernel.yama.ptrace_scope = 1",
			"",
		}, "\n")),
	}
	for _, plan := range []*EnclaveContainerPlan{agents, edit} {
		files[plan.MachineName+enclaveContainerFilesNspawn] = enclaveContainerNspawnFile(plan)
	}
	return files, nil
}

// A plan's nspawn settings file (systemd.nspawn(5)), its scope's properties as comments, since they are
// systemd-run's.
func enclaveContainerNspawnFile(plan *EnclaveContainerPlan) []byte {
	lines := []string{
		"# Generated from DefaultEnclaveContainerSettings by EnclaveContainerFiles (enclave_container_runtime.go);",
		"# TestEnclaveContainerFilesAreCurrent holds it. The " + string(plan.Role) + " container's plan (DESIGN-COMPUTE §11.10, §12.9),",
		"# for review: the daemon passes the whole plan on systemd-nspawn's command line with --settings=no.",
		"# Its scope, " + plan.SliceName + "/" + plan.ScopeName + ", runs under systemd-run with these properties:",
	}
	for _, property := range plan.ScopeProperties {
		lines = append(lines, "#   "+property)
	}
	lines = append(lines,
		"",
		"[Exec]",
		"Boot=no",
		"Parameters="+strings.Join(plan.InitArgv, " "),
		fmt.Sprintf("PrivateUsers=%d:%d", plan.UidBase, plan.UidCount),
		"KillSignal="+enclaveContainerKillSignal,
		fmt.Sprintf("OOMScoreAdjust=%d", plan.OomScoreAdjust),
		"SystemCallFilter=~"+strings.Join(plan.DeniedSystemCalls, " "),
		"LinkJournal=no",
		"ResolvConf=off",
		"",
		"[Files]",
		"PrivateUsersOwnership=map",
	)
	for _, mount := range plan.Mounts {
		key := "Bind="
		if mount.ReadOnly {
			key = "BindReadOnly="
		}
		spec := mount.Source + ":" + mount.Target
		if mount.Idmap {
			spec += ":idmap"
		}
		lines = append(lines, key+spec)
	}
	for _, device := range plan.Devices {
		lines = append(lines, "Bind="+device)
	}
	lines = append(lines,
		"",
		"[Network]",
		"VirtualEthernet=yes",
		"",
	)
	return []byte(strings.Join(lines, "\n"))
}
