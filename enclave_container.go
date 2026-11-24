//go:build !ios_extension && !sidecar_http

// The agents' container and the edit container (DESIGN-COMPUTE §11.10, §12.9; D-ENC-6, D-ENC-13, IC-14, IC-23,
// R-CCTX-29; Q-ENC-3's answer c, QD-1294): agents get root for everything Debian offers inside a container of their
// own, while the incarnation's keys, the daemon, the Harness and the enclave's routes and firewall stay in namespaces
// the container cannot enter.
//
//	agents     a Debian root file system, an overlay on the image's read-only root (RootFsPath) whose upper layer
//	           sits on the scratch volume, so apt, services, low ports, gdb and strace work there as root; its own
//	           user namespace, its root an unprivileged uid outside (UidBase), and its own PID, mount, IPC, UTS and
//	           network namespaces; its veth routed through ur tun and the daemon's rules, taking only its own
//	           source address; Yama's ptrace_scope left at Debian's 1; ur bound in read-only; one socket bound in,
//	           the container socket (enclave_container_socket.go); no TEE interface and no credential but the
//	           gateway's hour-long tokens (IC-11)
//	edit       the person-only container of §12.9: the same shape with a user namespace of its own, the agents'
//	           root file system at /agents, its veth routed as the agents', and no container socket; no agent
//	           process enters or writes it
//	boundary   a seccomp filter over the runtime's own (enclave_container_seccomp.go): no nested user namespaces,
//	           io_uring off, BPF off; the kernel's unprivileged BPF and io_uring switched off as well, which Start
//	           checks before anything runs; cgroup limits on memory, CPU and tasks in a scope of its own, leaving
//	           the daemon its share; the OOM killer taking the container before the daemon
//	network    nothing in the enclave's namespaces takes input from a veth but the daemon's DNS port: that and the
//	           source rule are the host firewall's (EnclaveContainerFirewall, ENC-M14-11's EnclaveHostFirewall), and
//	           Start refuses to run a container with no firewall to admit its veth, before the veth can carry a
//	           packet; the veth's host end also drops a source outside its prefix by strict reverse-path filtering
//	hooks      Exec runs a tool process or an SSH session's program inside a running container's namespaces, under
//	           the same filter (HARN's bash, git and pig; SSH.md's agent and edit sessions); RootHandle is an O_PATH
//	           descriptor of the container's root, for the Harness's file tools to open beneath with openat2's
//	           RESOLVE_IN_ROOT (EnclaveContainerOpenInRoot); ListenInNamespace opens a listener on the container's
//	           own loopback, in its network namespace, for the gateway (GW C§8.7); LeaderPid names the container's
//	           first process, whose namespaces the daemon, root outside, reads for LSTN's socket tables
//
// Everything a container is is its plan (EnclaveContainerPlan), data on every leg; the runtime turns the plan into
// commands (enclave_container_runtime.go: systemd-nspawn, the design's, or gVisor's runsc for D-ENC-13's evaluation),
// and the system does what the kernel must (EnclaveContainerSystem: enclave_container_linux.go on the enclave's leg,
// a test's elsewhere). An EnclaveContainer is safe for concurrent use.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path"
	"slices"
	"strings"
	"sync"
	"time"
)

// Which container a plan is.
type EnclaveContainerRole string

const (
	// The agents' container (§11.10).
	EnclaveContainerRoleAgents EnclaveContainerRole = "agents"
	// The person-only edit container (§12.9).
	EnclaveContainerRoleEdit EnclaveContainerRole = "edit"
)

// Which runtime runs the containers.
type EnclaveContainerRuntimeName string

const (
	// systemd-nspawn, the design's (§11.10).
	EnclaveContainerRuntimeNspawn EnclaveContainerRuntimeName = "nspawn"
	// gVisor's runsc over an OCI bundle of the same root, for D-ENC-13's evaluation alone (§11.14): adopted only once
	// apt, builds and the network tools pass under it, which is an outside party's run.
	EnclaveContainerRuntimeRunsc EnclaveContainerRuntimeName = "runsc"
)

// Format values of the runtimes and the kernel, which name things rather than limit them.
const (
	// nspawn's veth: the host end is ve-<machine>, the container end host0.
	enclaveContainerVethHostPrefix = "ve-"
	enclaveContainerVethContainer  = "host0"
	// The name ur answers to as the seccomp shim (enclave_container_linux.go): the container's first process, and
	// the process every Exec starts through, install the filter and then exec what follows "--".
	enclaveSeccompShimName = "ur-enclave-seccomp"
	// nspawn's signal for a clean poweroff of a container whose first process is systemd.
	enclaveContainerKillSignal = "SIGRTMIN+3"
	// Where the edit container sees the agents' root file system (§12.9).
	enclaveEditAgentsMountPath = "/agents"
)

// The paths through which a TEE's evidence or keys are reached, which no container may name (§11.10): TDX's and
// SEV-SNP's guest devices, any TPM, configfs (configfs-tsm) and securityfs.
var enclaveContainerTeePaths = []string{
	"/dev/tdx_guest", "/dev/tdx-guest", "/dev/sev-guest", "/dev/sev", "/dev/tpm", "/sys/kernel/config", "/sys/kernel/security",
}

var (
	// A setting a container cannot run with: a relative path, a name the runtime cannot take, overlapping user
	// namespaces, a device that is a TEE interface.
	ErrEnclaveContainerSettings = errors.New("invalid enclave container settings")
	// The container is not running, or not in the state the call needs.
	ErrEnclaveContainerState = errors.New("the enclave container is not in a state for this")
	// No firewall admits the container's veth (ENC-M14-11), so nothing starts: the veth's boundary is the firewall's
	// rules, and a container without them could reach the enclave's own listeners.
	ErrEnclaveContainerNoFirewall = errors.New("no host firewall admits the container's veth, so the container does not start")
	// The kernel lacks a setting the boundary needs, or the system cannot say.
	ErrEnclaveContainerKernel = errors.New("the kernel does not hold the container's boundary")
	// The container's first process did not appear within StartTimeout.
	ErrEnclaveContainerStartTimeout = errors.New("the enclave container did not start in time")
	// The container's runtime exited.
	ErrEnclaveContainerExited = errors.New("the enclave container's runtime exited")
	// This build runs no containers: only the enclave's (linux && ur_enclave) has a system for them.
	ErrEnclaveContainerUnsupported = errors.New("this build runs no enclave containers")
	// A call the container refuses: an Exec with no program or a malformed environment, a listener off loopback.
	ErrEnclaveContainerRefused = errors.New("refused by the enclave container")
)

// One container's settings (§11.10, §12.9).
type EnclaveContainerRoleSettings struct {
	// The machine's name, which names its veth's host end (ve-<name>), its scope (<name>.scope) and its directories
	// on the scratch volume: letters, digits and '-', short enough that ve-<name> fits an interface name.
	MachineName string
	// The first uid and gid outside its user namespace: its root is this uid outside, unprivileged (Q-ENC-3). Each
	// container's range is its own, and none overlaps another's or the system's.
	UidBase uint32
	// How many uids and gids its user namespace maps: 65536, the 16-bit range Debian's packages use.
	UidCount uint32
	// The veth's host end's address and prefix: the container's gateway and its one nameserver. A /30 holds the two
	// ends and no third address the container could take.
	HostPrefix netip.Prefix
	// The container end's address: the only source address its veth takes.
	ContainerAddress netip.Addr
	// Its scope's memory ceiling as a percentage of the VM's memory (systemd's MemoryMax=): the agents' 75, the
	// editor's 25, leaving the daemon what it needs. Non-positive sets none.
	MemoryMaxPercent int
	// Its scope's CPU weight against the daemon's default 100 (systemd's CPUWeight=): the agents' 50 and the
	// editor's 25, so under contention the daemon is served first. Non-positive sets none.
	CpuWeight int
	// The most tasks, processes and threads, its scope holds (systemd's TasksMax=): the agents' 8192, past a
	// parallel build's, and the editor's 2048, past an editor's server. Non-positive sets none.
	TasksMax int
	// The OOM score adjustment its processes start with: 500, so under memory pressure the kernel takes the
	// container's processes before the daemon's. The kernel's range, -1000 to 1000, which nspawn holds it to.
	OomScoreAdjust int
	// Device nodes it takes beyond the runtime's basic set, each a path under /dev: none by default; M15's GPU
	// enclaves name their GPUs' (ENC-M15-01). A TEE interface is never one (§11.10).
	Devices []string
}

// The containers' settings (§11.10): their runtime, the tools that run them, their paths, and each container's own.
type EnclaveContainerSettings struct {
	// Which runtime runs them: nspawn, the design's, or runsc, for D-ENC-13's evaluation alone.
	Runtime EnclaveContainerRuntimeName
	// systemd-run, which starts each container in a scope of its own whose limits leave the daemon its share.
	SystemdRunPath string
	// systemd-nspawn.
	NspawnPath string
	// util-linux's nsenter, which an Exec runs to enter a running container's namespaces.
	NsenterPath string
	// gVisor's runsc, built from ROOT/gvisor into the image; read only when Runtime is runsc.
	RunscPath string
	// runsc's state directory, its --root; read only when Runtime is runsc.
	RunscStatePath string
	// The ur binary outside, which each container takes read-only.
	UrPath string
	// Where ur sits in a container, on its PATH, read-only (§11.10).
	UrMountPath string
	// Where ur sits again in a container, under the seccomp shim's name, so the container's first process is the
	// shim: it installs the filter, then execs InitPath.
	SeccompShimMountPath string
	// The container's init, which the shim execs once the filter holds: systemd, so services run.
	InitPath string
	// The image's Debian root file system for the containers, read-only and measured: the overlay's lower layer.
	RootFsPath string
	// Where each container keeps its overlay's upper layer, work directory and merged root, and its resolv.conf, on
	// the scratch volume (ENC-M14-11's dm-crypt and dm-integrity volume).
	ScratchPath string
	// The cgroup file system, where each container's scope and its Exec leaf live.
	CgroupPath string
	// The slice every container's scope runs in.
	SliceName string
	// The PATH an Exec'd process gets when its environment names none: Debian's root PATH.
	ExecSearchPath string
	// The DNS port the daemon serves the containers on, at each veth's host address: 53, the protocol's. The one
	// port in the enclave's namespaces a veth reaches (§11.10).
	DnsPort int
	// The longest interface name Linux takes, IFNAMSIZ less its terminator: 15, the kernel's. A machine name must
	// leave its veth's host end, ve-<name>, within it.
	InterfaceNameMaxByteCount int
	// How long Start waits for the container's first process: 60 s, a cold systemd boot of the overlay on a busy
	// scratch volume.
	StartTimeout time.Duration
	// How often Start looks for the first process while it waits: 100 ms. Positive.
	StartPollInterval time.Duration
	// How long Stop waits for the container to power off before it kills it: 30 s, systemd's own stop timeouts
	// with room.
	StopTimeout time.Duration
	// The agents' container (§11.10).
	Agents *EnclaveContainerRoleSettings
	// The edit container (§12.9).
	Edit *EnclaveContainerRoleSettings
	// The container socket (ENC-M14-14), which only the agents' container takes.
	Socket *EnclaveContainerSocketSettings
}

// The design's values (§11.10, §12.9): the image's tools at Debian's paths, systemd's container uid ranges, and a /30
// per veth from the design's 10.88.0.0 (§26.9's 10.88.0.2 is the agents').
func DefaultEnclaveContainerSettings() *EnclaveContainerSettings {
	return &EnclaveContainerSettings{
		Runtime:                   EnclaveContainerRuntimeNspawn,
		SystemdRunPath:            "/usr/bin/systemd-run",
		NspawnPath:                "/usr/bin/systemd-nspawn",
		NsenterPath:               "/usr/bin/nsenter",
		RunscPath:                 "/usr/lib/ur/runsc",
		RunscStatePath:            "/run/ur/runsc",
		UrPath:                    "/usr/bin/ur",
		UrMountPath:               "/usr/local/bin/ur",
		SeccompShimMountPath:      "/usr/local/lib/ur/" + enclaveSeccompShimName,
		InitPath:                  "/lib/systemd/systemd",
		RootFsPath:                "/usr/lib/ur/container/rootfs",
		ScratchPath:               "/var/lib/ur/scratch/containers",
		CgroupPath:                "/sys/fs/cgroup",
		SliceName:                 "ur-containers.slice",
		ExecSearchPath:            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		DnsPort:                   53,
		InterfaceNameMaxByteCount: 15,
		StartTimeout:              60 * time.Second,
		StartPollInterval:         100 * time.Millisecond,
		StopTimeout:               30 * time.Second,
		Agents: &EnclaveContainerRoleSettings{
			MachineName:      "ur-agents",
			UidBase:          0x00080000,
			UidCount:         0x00010000,
			HostPrefix:       netip.MustParsePrefix("10.88.0.1/30"),
			ContainerAddress: netip.MustParseAddr("10.88.0.2"),
			MemoryMaxPercent: 75,
			CpuWeight:        50,
			TasksMax:         8192,
			OomScoreAdjust:   500,
			Devices:          []string{},
		},
		Edit: &EnclaveContainerRoleSettings{
			MachineName:      "ur-edit",
			UidBase:          0x00090000,
			UidCount:         0x00010000,
			HostPrefix:       netip.MustParsePrefix("10.88.0.5/30"),
			ContainerAddress: netip.MustParseAddr("10.88.0.6"),
			MemoryMaxPercent: 25,
			CpuWeight:        25,
			TasksMax:         2048,
			OomScoreAdjust:   500,
			Devices:          []string{},
		},
		Socket: DefaultEnclaveContainerSocketSettings(),
	}
}

// The container socket's settings (enclave_container_socket.go), which only the agents' container takes.
type EnclaveContainerSocketSettings struct {
	// The socket's path outside, in a directory only root reaches; the directory is bound read-only into the agents'
	// container, and never into the edit container.
	Path string
	// Where the socket appears in the agents' container: the bound directory, holding it under its own name.
	MountPath string
	// How many sessions may be open at once: 64, past every harness, relay and hook the agents run at once. One past
	// it is refused. Positive.
	SessionCount int
}

// The design's values.
func DefaultEnclaveContainerSocketSettings() *EnclaveContainerSocketSettings {
	return &EnclaveContainerSocketSettings{
		Path:         "/run/ur/container/ur.sock",
		MountPath:    "/run/ur/ur.sock",
		SessionCount: 64,
	}
}

// Holds the socket's settings to what it can serve with.
func (self *EnclaveContainerSocketSettings) check() error {
	if !enclaveContainerPathOk(self.Path) || !enclaveContainerPathOk(self.MountPath) || path.Base(self.Path) != path.Base(self.MountPath) {
		return fmt.Errorf("%w: the container socket's paths", ErrEnclaveContainerSettings)
	}
	if path.Dir(self.Path) == "/" || path.Dir(self.MountPath) == "/" {
		return fmt.Errorf("%w: the container socket needs a directory of its own", ErrEnclaveContainerSettings)
	}
	if self.SessionCount <= 0 {
		return fmt.Errorf("%w: the container socket's session count", ErrEnclaveContainerSettings)
	}
	return nil
}

// The role's own settings.
func (self *EnclaveContainerSettings) role(role EnclaveContainerRole) (*EnclaveContainerRoleSettings, error) {
	switch role {
	case EnclaveContainerRoleAgents:
		if self.Agents != nil {
			return self.Agents, nil
		}
	case EnclaveContainerRoleEdit:
		if self.Edit != nil {
			return self.Edit, nil
		}
	}
	return nil, fmt.Errorf("%w: no settings for the %q container", ErrEnclaveContainerSettings, role)
}

// Whether a path is one a runtime's arguments can carry whole: absolute, clean, and free of the separators nspawn's
// binds and overlayfs's options split on.
func enclaveContainerPathOk(value string) bool {
	return path.IsAbs(value) && path.Clean(value) == value && !strings.ContainsAny(value, ":,\\\n\x00 ")
}

// Whether a path is, or sits beneath, one of the TEE interfaces.
func enclaveContainerTeePath(value string) bool {
	cleaned := path.Clean(value)
	return slices.ContainsFunc(enclaveContainerTeePaths, func(teePath string) bool {
		return cleaned == teePath || strings.HasPrefix(cleaned, teePath+"/") ||
			(teePath == "/dev/tpm" && strings.HasPrefix(cleaned, teePath))
	})
}

// Whether a machine name is one nspawn takes and whose veth name fits within maxByteCount.
func enclaveContainerMachineNameOk(name string, maxByteCount int) bool {
	if name == "" || maxByteCount < len(enclaveContainerVethHostPrefix)+len(name) {
		return false
	}
	for _, r := range name {
		if !('a' <= r && r <= 'z' || 'A' <= r && r <= 'Z' || '0' <= r && r <= '9' || r == '-') {
			return false
		}
	}
	return name[0] != '-' && name[len(name)-1] != '-'
}

// Holds the settings to what a container can run with, each failure ErrEnclaveContainerSettings.
func (self *EnclaveContainerSettings) check() error {
	fail := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", ErrEnclaveContainerSettings, fmt.Sprintf(format, args...))
	}
	if self.Runtime != EnclaveContainerRuntimeNspawn && self.Runtime != EnclaveContainerRuntimeRunsc {
		return fail("the runtime %q", self.Runtime)
	}
	paths := []string{self.SystemdRunPath, self.NspawnPath, self.NsenterPath, self.UrPath, self.UrMountPath,
		self.SeccompShimMountPath, self.InitPath, self.RootFsPath, self.ScratchPath, self.CgroupPath}
	if self.Runtime == EnclaveContainerRuntimeRunsc {
		paths = append(paths, self.RunscPath, self.RunscStatePath)
	}
	for _, value := range paths {
		if !enclaveContainerPathOk(value) {
			return fail("the path %q is not absolute and clean", value)
		}
	}
	if path.Base(self.SeccompShimMountPath) != enclaveSeccompShimName {
		return fail("the seccomp shim's mount must be named %s", enclaveSeccompShimName)
	}
	if !strings.HasSuffix(self.SliceName, ".slice") || strings.ContainsAny(self.SliceName, "/:, ") {
		return fail("the slice %q", self.SliceName)
	}
	if self.DnsPort <= 0 || int(uint16(self.DnsPort)) != self.DnsPort {
		return fail("the DNS port %d", self.DnsPort)
	}
	if self.StartTimeout <= 0 || self.StartPollInterval <= 0 || self.StopTimeout <= 0 {
		return fail("a non-positive start, poll or stop time")
	}
	roles := []*EnclaveContainerRoleSettings{self.Agents, self.Edit}
	for i, role := range roles {
		if role == nil {
			return fail("a container has no settings")
		}
		if !enclaveContainerMachineNameOk(role.MachineName, self.InterfaceNameMaxByteCount) {
			return fail("the machine name %q", role.MachineName)
		}
		if role.UidBase == 0 || role.UidCount == 0 || role.UidBase+role.UidCount < role.UidBase {
			return fail("%s's user namespace range", role.MachineName)
		}
		if !role.HostPrefix.IsValid() || !role.HostPrefix.Addr().Is4() || !role.ContainerAddress.Is4() ||
			!role.HostPrefix.Contains(role.ContainerAddress) || role.HostPrefix.Addr() == role.ContainerAddress ||
			role.HostPrefix.Masked().Addr() == role.ContainerAddress {
			return fail("%s's veth addresses", role.MachineName)
		}
		for _, device := range role.Devices {
			if !enclaveContainerPathOk(device) || !strings.HasPrefix(device, "/dev/") || enclaveContainerTeePath(device) {
				return fail("%s's device %q", role.MachineName, device)
			}
		}
		for _, other := range roles[i+1:] {
			if other == nil {
				continue
			}
			if role.MachineName == other.MachineName {
				return fail("two containers named %s", role.MachineName)
			}
			if role.UidBase < other.UidBase+other.UidCount && other.UidBase < role.UidBase+role.UidCount {
				return fail("%s's and %s's user namespaces overlap", role.MachineName, other.MachineName)
			}
			if role.HostPrefix.Overlaps(other.HostPrefix) {
				return fail("%s's and %s's veths overlap", role.MachineName, other.MachineName)
			}
		}
	}
	if self.Socket == nil {
		return fail("no container socket settings")
	}
	return self.Socket.check()
}

// A container's veth (§11.10): what the system configures and the host firewall admits.
type EnclaveContainerNetwork struct {
	// The machine the veth belongs to.
	MachineName string
	// The host end, ve-<machine>.
	HostInterface string
	// The container end, host0.
	ContainerInterface string
	// The host end's address and prefix: the container's gateway and its one nameserver.
	HostPrefix netip.Prefix
	// The only source address the veth takes.
	ContainerAddress netip.Addr
	// The daemon's DNS port at the host end's address: the one input the enclave's namespaces take from the veth.
	DnsPort int
}

// One path a container takes from outside.
type EnclaveContainerMount struct {
	// The path outside.
	Source string
	// The path inside.
	Target   string
	ReadOnly bool
	// Whether the mount maps its source's owners on disk into the container's user namespace (an idmapped mount),
	// so the container's root owns what root owns on disk.
	Idmap bool
}

// A container as data: everything a runtime needs to start it and the system needs to place it (TestEnclaveContainerPlan).
type EnclaveContainerPlan struct {
	Role        EnclaveContainerRole
	MachineName string
	// The overlay: the image's root below, its upper layer and work directory above, and the root they make.
	LowerPath string
	UpperPath string
	WorkPath  string
	RootPath  string
	// The container's directory on the scratch volume, which holds the four above and its files.
	StatePath string
	// Its user namespace: UidBase outside is its root.
	UidBase  uint32
	UidCount uint32
	Network  *EnclaveContainerNetwork
	Mounts   []*EnclaveContainerMount
	// The device nodes beyond the runtime's basic set.
	Devices []string
	// Its scope and the slice the scope runs in, and the scope's properties as systemd's name=value.
	ScopeName       string
	SliceName       string
	ScopeProperties []string
	// The scope's cgroup directory, which systemd-run makes and a kill of the container ends whole.
	ScopeCgroupPath string
	// The cgroup directory each Exec'd process gets a leaf of its own beneath: beside the runtime's, under the
	// scope's limits.
	ExecCgroupPath string
	OomScoreAdjust int
	// The system calls the runtime's own filter drops beside its default (nspawn's --system-call-filter=~).
	DeniedSystemCalls []string
	// The container's first process: the seccomp shim, then the init.
	InitArgv []string
	// The files the container's start writes outside it, by path: its resolv.conf, and a runtime's own.
	Files map[string][]byte
	// The resolv.conf the container takes read-only: the veth's host end as its one nameserver.
	ResolvConfPath string
	// The Exec shim: ur outside, run under the shim's name.
	UrPath      string
	NsenterPath string
	// The PATH an Exec'd process gets when its environment names none.
	ExecSearchPath string
}

// The plan of role's container on settings; for the edit container, agentsRootPath is the agents' container's root,
// which it sees at /agents. Holds the settings first.
func NewEnclaveContainerPlan(settings *EnclaveContainerSettings, role EnclaveContainerRole, agentsRootPath string) (*EnclaveContainerPlan, error) {
	if settings == nil {
		return nil, fmt.Errorf("%w: none", ErrEnclaveContainerSettings)
	}
	if err := settings.check(); err != nil {
		return nil, err
	}
	roleSettings, err := settings.role(role)
	if err != nil {
		return nil, err
	}
	statePath := path.Join(settings.ScratchPath, roleSettings.MachineName)
	plan := &EnclaveContainerPlan{
		Role:        role,
		MachineName: roleSettings.MachineName,
		LowerPath:   settings.RootFsPath,
		UpperPath:   path.Join(statePath, "upper"),
		WorkPath:    path.Join(statePath, "work"),
		RootPath:    path.Join(statePath, "root"),
		StatePath:   statePath,
		UidBase:     roleSettings.UidBase,
		UidCount:    roleSettings.UidCount,
		Network: &EnclaveContainerNetwork{
			MachineName:        roleSettings.MachineName,
			HostInterface:      enclaveContainerVethHostPrefix + roleSettings.MachineName,
			ContainerInterface: enclaveContainerVethContainer,
			HostPrefix:         roleSettings.HostPrefix,
			ContainerAddress:   roleSettings.ContainerAddress,
			DnsPort:            settings.DnsPort,
		},
		Devices:        slices.Clone(roleSettings.Devices),
		ScopeName:      roleSettings.MachineName + ".scope",
		SliceName:      settings.SliceName,
		OomScoreAdjust: roleSettings.OomScoreAdjust,
		// nspawn's default allows io_uring (its @aio) and userfaultfd; the shim's filter drops them too, and more
		DeniedSystemCalls: []string{"io_uring_setup", "io_uring_enter", "io_uring_register", "userfaultfd"},
		InitArgv:          []string{settings.SeccompShimMountPath, "--", settings.InitPath},
		ResolvConfPath:    path.Join(statePath, "resolv.conf"),
		UrPath:            settings.UrPath,
		NsenterPath:       settings.NsenterPath,
		ExecSearchPath:    settings.ExecSearchPath,
	}
	plan.ScopeCgroupPath = path.Join(settings.CgroupPath, enclaveContainerSliceCgroupPath(settings.SliceName), plan.ScopeName)
	plan.ExecCgroupPath = path.Join(plan.ScopeCgroupPath, "ur-exec")
	plan.Files = map[string][]byte{
		plan.ResolvConfPath: []byte(fmt.Sprintf("nameserver %s\n", roleSettings.HostPrefix.Addr())),
	}
	plan.Mounts = []*EnclaveContainerMount{
		// ur on the PATH and as the seccomp shim, read-only from outside (§11.10)
		{Source: settings.UrPath, Target: settings.UrMountPath, ReadOnly: true},
		{Source: settings.UrPath, Target: settings.SeccompShimMountPath, ReadOnly: true},
		// its one nameserver, the daemon's DNS at the veth's host end
		{Source: plan.ResolvConfPath, Target: "/etc/resolv.conf", ReadOnly: true},
	}
	switch role {
	case EnclaveContainerRoleAgents:
		// the container socket, which the agents' container alone takes (ENC-M14-14)
		plan.Mounts = append(plan.Mounts, &EnclaveContainerMount{
			Source: path.Dir(settings.Socket.Path), Target: path.Dir(settings.Socket.MountPath), ReadOnly: true,
		})
	case EnclaveContainerRoleEdit:
		if !enclaveContainerPathOk(agentsRootPath) {
			return nil, fmt.Errorf("%w: the edit container needs the agents' root", ErrEnclaveContainerSettings)
		}
		// the agents' files, which the person edits, owned in the edit container as in the agents' (§12.9)
		plan.Mounts = append(plan.Mounts, &EnclaveContainerMount{Source: agentsRootPath, Target: enclaveEditAgentsMountPath, Idmap: true})
	}
	plan.ScopeProperties = []string{
		// nspawn and the container's systemd manage the scope's subtree
		"Delegate=yes",
		// the standard pseudo devices, a tun and ptys, and the listed devices alone; never a TEE interface
		"DevicePolicy=closed",
		"DeviceAllow=/dev/net/tun rwm",
		"DeviceAllow=char-pts rw",
	}
	for _, device := range plan.Devices {
		plan.ScopeProperties = append(plan.ScopeProperties, "DeviceAllow="+device+" rw")
	}
	if 0 < roleSettings.MemoryMaxPercent {
		plan.ScopeProperties = append(plan.ScopeProperties, fmt.Sprintf("MemoryMax=%d%%", roleSettings.MemoryMaxPercent))
	}
	if 0 < roleSettings.CpuWeight {
		plan.ScopeProperties = append(plan.ScopeProperties, fmt.Sprintf("CPUWeight=%d", roleSettings.CpuWeight))
	}
	if 0 < roleSettings.TasksMax {
		plan.ScopeProperties = append(plan.ScopeProperties, fmt.Sprintf("TasksMax=%d", roleSettings.TasksMax))
	}
	if err := plan.checkBoundary(); err != nil {
		return nil, err
	}
	return plan, nil
}

// A slice's cgroup path below the cgroup root, as systemd nests a slice by its name's dashes: a-b.slice is
// a.slice/a-b.slice.
func enclaveContainerSliceCgroupPath(slice string) string {
	name := strings.TrimSuffix(slice, ".slice")
	parts := strings.Split(name, "-")
	nested := []string{}
	for i := range parts {
		nested = append(nested, strings.Join(parts[:i+1], "-")+".slice")
	}
	return path.Join(nested...)
}

// Holds a plan to the container's boundary (§11.10), whatever made it: ur only read-only, no TEE interface named by
// a mount or a device, the container socket only in the agents' container, and no mount of the daemon's own state.
func (self *EnclaveContainerPlan) checkBoundary() error {
	fail := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", ErrEnclaveContainerSettings, fmt.Sprintf(format, args...))
	}
	for _, device := range self.Devices {
		if enclaveContainerTeePath(device) {
			return fail("the device %s is a TEE interface", device)
		}
	}
	for _, mount := range self.Mounts {
		if enclaveContainerTeePath(mount.Source) || enclaveContainerTeePath(mount.Target) {
			return fail("the mount of %s is a TEE interface", mount.Source)
		}
		if mount.Source == self.UrPath && !mount.ReadOnly {
			return fail("ur is not read-only")
		}
		if !enclaveContainerPathOk(mount.Source) || !enclaveContainerPathOk(mount.Target) {
			return fail("the mount of %s", mount.Source)
		}
	}
	return nil
}

// The mount whose target is target, nil for none.
func (self *EnclaveContainerPlan) mountAt(target string) *EnclaveContainerMount {
	for _, mount := range self.Mounts {
		if mount.Target == target {
			return mount
		}
	}
	return nil
}

// One process to run inside a running container (Exec): HARN's tool processes, SSH.md's sessions' programs.
type EnclaveContainerExec struct {
	// The user inside the container: "root", or "<uid>:<gid>" in the container's own ids. Agents run as root
	// (§11.10).
	User string
	// The program and its arguments; the program an absolute path inside the container, or a name its PATH finds.
	Argv []string
	// Exactly the environment the process gets, each KEY=value; one with no PATH gets ExecSearchPath. It holds no
	// key, token or link secret of the daemon's (IC-14): the caller builds it, and a gateway token is the one
	// credential a container process may hold (IC-11).
	Env []string
	// The working directory inside the container; empty is /.
	Dir    string
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

// The user's ids inside the container.
func (self *EnclaveContainerExec) ids() (uint32, uint32, error) {
	if self.User == "" || self.User == "root" {
		return 0, 0, nil
	}
	var uid uint32
	var gid uint32
	if _, err := fmt.Sscanf(self.User, "%d:%d", &uid, &gid); err != nil || fmt.Sprintf("%d:%d", uid, gid) != self.User {
		return 0, 0, fmt.Errorf("%w: the user %q is neither root nor uid:gid", ErrEnclaveContainerRefused, self.User)
	}
	return uid, gid, nil
}

// The environment the process gets: each KEY=value checked, and ExecSearchPath when none names PATH.
func (self *EnclaveContainerExec) environment(searchPath string) ([]string, error) {
	env := []string{}
	hasPath := false
	for _, entry := range self.Env {
		key, _, ok := strings.Cut(entry, "=")
		if !ok || key == "" || strings.ContainsAny(entry, "\x00") {
			return nil, fmt.Errorf("%w: an environment entry is not KEY=value", ErrEnclaveContainerRefused)
		}
		hasPath = hasPath || key == "PATH"
		env = append(env, entry)
	}
	if !hasPath {
		env = append(env, "PATH="+searchPath)
	}
	return env, nil
}

// One command the system runs outside a container: the runtime's supervisor, or an Exec's shim.
type EnclaveContainerCommand struct {
	// The program's path and its arguments.
	Argv []string
	// argv[0] as the process sees it, when it differs from Argv[0]: the seccomp shim's name. Empty is Argv[0].
	Name string
	Env  []string
	// The cgroup directory a kill of the process ends whole, empty for none: an Exec's ExecCgroupPath, beneath which
	// the system makes the process a leaf of its own and starts it there (CLONE_INTO_CGROUP), so it and its children
	// are under the container's limits from their first instruction; or a supervisor's scope, which systemd-run
	// makes and the container's every process runs in.
	CgroupPath string
	// Whether the system makes the process its own leaf beneath CgroupPath and starts it in it: an Exec's.
	CgroupLeaf bool
	Stdin      io.Reader
	Stdout     io.Writer
	Stderr     io.Writer
}

// A process the system started. Safe for concurrent use; Wait is called once.
type EnclaveContainerProcess interface {
	// Its pid as the daemon's namespaces see it.
	Pid() int
	// Waits for it to exit: its exit code, or an error when it did not exit by itself.
	Wait() (int, error)
	// Sends a signal to its process group, which for an Exec holds the program inside the container too.
	Signal(signal os.Signal) error
	// Asks it to end: SIGTERM, which nspawn turns into the container's poweroff.
	Terminate() error
	// Ends it and everything it started, wherever they went: its cgroup's every process (cgroup.kill).
	Kill() error
}

// What the kernel must do for a container (enclave_container_linux.go on the enclave's leg; a test's elsewhere). Safe
// for concurrent use.
type EnclaveContainerSystem interface {
	// Checks the kernel settings the boundary needs: unprivileged BPF off, io_uring off where the kernel can say. An
	// error, ErrEnclaveContainerKernel, names the first that does not hold.
	CheckKernel() error
	// Makes the container's directories, writes its files and mounts its overlay at RootPath, unless one is there.
	PrepareRoot(ctx context.Context, plan *EnclaveContainerPlan) error
	// Unmounts the overlay, keeping its upper layer for the next start in this incarnation.
	ReleaseRoot(plan *EnclaveContainerPlan) error
	// Starts the runtime's supervisor, which runs the container in the foreground until it ends.
	Start(ctx context.Context, command *EnclaveContainerCommand) (EnclaveContainerProcess, error)
	// The container's first process, its pid as the daemon sees it, once it runs; 0 with no error until then.
	Leader(plan *EnclaveContainerPlan) (int, error)
	// Makes the Exec cgroup beside the runtime's, under the scope's limits, once the scope exists.
	PrepareExecCgroup(plan *EnclaveContainerPlan) error
	// Configures the veth's two ends once the first process runs: the host end's address and its reverse-path
	// filter, the container end's address and its default route through the host end, both up.
	ConfigureNetwork(ctx context.Context, leaderPid int, network *EnclaveContainerNetwork) error
	// Opens the first process's root, O_PATH: the container's root as its processes see it.
	OpenRoot(leaderPid int) (*os.File, error)
	// A new descriptor of file's, which the caller owns; an error once file is closed.
	Dup(file *os.File) (*os.File, error)
	// Runs a command outside, an Exec's shim.
	Run(ctx context.Context, command *EnclaveContainerCommand) (EnclaveContainerProcess, error)
	// Opens a listener in the first process's network namespace, on a thread of the daemon's own that returns to
	// the daemon's namespace.
	Listen(leaderPid int, network string, address string) (net.Listener, error)
	// Whether pid runs in the first process's PID namespace, and its pid there.
	NamespacePid(pid int, leaderPid int) (int, bool)
}

// What admits a container's veth (§11.10, IC-8): ENC-M14-11's EnclaveHostFirewall. Safe for concurrent use.
type EnclaveContainerFirewall interface {
	// Installs the veth's rules, read back before it returns: the veth's packets taken only from its container's
	// address and only through ur tun and the daemon's rules, and nothing in the enclave's namespaces taking input
	// from it but the daemon's DNS port. Called before the veth can carry a packet; an error starts nothing.
	AdmitContainer(ctx context.Context, network *EnclaveContainerNetwork) error
	// Removes them once the container is gone.
	WithdrawContainer(ctx context.Context, network *EnclaveContainerNetwork) error
}

// What NewEnclaveContainer takes.
type EnclaveContainerArgs struct {
	// Nil is DefaultEnclaveContainerSettings.
	Settings *EnclaveContainerSettings
	Role     EnclaveContainerRole
	// The edit container's: the agents' container's root, which it sees at /agents.
	AgentsRootPath string
	// Nil is the build's: the enclave's on its leg, else none, and Start refuses.
	System EnclaveContainerSystem
	// Nil refuses to start (ErrEnclaveContainerNoFirewall), the closed side until ENC-M14-11 lands.
	Firewall EnclaveContainerFirewall
	// Nil is real time.
	Clock Clock
	// Nil is no logging.
	Log Logger
}

// The build's system: the enclave's leg sets it (enclave_container_linux.go); nil elsewhere.
var enclaveContainerBuildSystem func() EnclaveContainerSystem

// A container process's credentials as the daemon's namespaces see them (SO_PEERCRED), which the container socket
// binds its callers by (enclave_container_socket.go).
type EnclaveContainerPeer struct {
	Pid int
	Uid uint32
	Gid uint32
}

// The build's peer reader: the enclave's leg sets it (enclave_container_linux.go); nil elsewhere, which refuses every
// caller.
var enclaveContainerBuildPeer func(conn net.Conn) (EnclaveContainerPeer, error)

// A container's lifecycle.
type enclaveContainerState int

const (
	enclaveContainerStopped enclaveContainerState = iota
	enclaveContainerStarting
	enclaveContainerRunning
	enclaveContainerStopping
)

// One container: the agents', or the edit container's through EnclaveEditContainer.
type EnclaveContainer struct {
	settings *EnclaveContainerSettings
	plan     *EnclaveContainerPlan
	runtime  EnclaveContainerRuntime
	system   EnclaveContainerSystem
	firewall EnclaveContainerFirewall
	clock    Clock
	log      Logger

	stateLock  sync.Mutex
	state      enclaveContainerState
	supervisor EnclaveContainerProcess
	// closed once the supervisor exited
	supervisorDone chan struct{}
	leaderPid      int
	root           *os.File
}

// A container of args.Role, stopped. The plan is made and checked here, so a container that cannot run is refused
// before anything starts.
func NewEnclaveContainer(args *EnclaveContainerArgs) (*EnclaveContainer, error) {
	settings := args.Settings
	if settings == nil {
		settings = DefaultEnclaveContainerSettings()
	}
	plan, err := NewEnclaveContainerPlan(settings, args.Role, args.AgentsRootPath)
	if err != nil {
		return nil, err
	}
	runtime, err := NewEnclaveContainerRuntime(settings)
	if err != nil {
		return nil, err
	}
	if err := runtime.Prepare(plan); err != nil {
		return nil, err
	}
	system := args.System
	if system == nil && enclaveContainerBuildSystem != nil {
		system = enclaveContainerBuildSystem()
	}
	log := args.Log
	if log == nil {
		log = NewNoopLogger()
	}
	return &EnclaveContainer{
		settings: settings,
		plan:     plan,
		runtime:  runtime,
		system:   system,
		firewall: args.Firewall,
		clock:    clockOrReal(args.Clock),
		log:      log,
	}, nil
}

// The container's plan, as data.
func (self *EnclaveContainer) Plan() *EnclaveContainerPlan {
	return self.plan
}

// Starts the container: the kernel's settings checked, its root prepared, its veth admitted by the firewall before
// it can carry a packet, the runtime started, its first process found, its veth configured and its root opened. A
// failure anywhere stops what started and answers the error; nothing is left half up.
func (self *EnclaveContainer) Start(ctx context.Context) error {
	if err := func() error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.state != enclaveContainerStopped {
			return fmt.Errorf("%w: it is not stopped", ErrEnclaveContainerState)
		}
		self.state = enclaveContainerStarting
		return nil
	}(); err != nil {
		return err
	}
	started := false
	defer func() {
		if !started {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.state = enclaveContainerStopped
		}
	}()
	if self.system == nil {
		return ErrEnclaveContainerUnsupported
	}
	if self.firewall == nil {
		return ErrEnclaveContainerNoFirewall
	}
	if err := self.system.CheckKernel(); err != nil {
		return err
	}
	if err := self.system.PrepareRoot(ctx, self.plan); err != nil {
		return err
	}
	if err := self.firewall.AdmitContainer(ctx, self.plan.Network); err != nil {
		self.releaseRoot()
		return fmt.Errorf("%w: %w", ErrEnclaveContainerNoFirewall, err)
	}
	command, err := self.runtime.StartCommand(self.plan)
	if err != nil {
		self.withdraw(ctx)
		self.releaseRoot()
		return err
	}
	command.CgroupPath = self.plan.ScopeCgroupPath
	supervisor, err := self.system.Start(ctx, command)
	if err != nil {
		self.withdraw(ctx)
		self.releaseRoot()
		return err
	}
	supervisorDone := make(chan struct{})
	go func() {
		defer close(supervisorDone)
		if _, err := supervisor.Wait(); err != nil && self.log.V(1).Enabled() {
			self.log.Infof("[enclave]the %s container's runtime ended: %s", self.plan.MachineName, err)
		}
	}()
	fail := func(err error) error {
		self.kill(supervisor, supervisorDone)
		self.withdraw(ctx)
		self.releaseRoot()
		return err
	}
	leaderPid, err := self.waitLeader(ctx, supervisorDone)
	if err != nil {
		return fail(err)
	}
	if err := self.system.PrepareExecCgroup(self.plan); err != nil {
		return fail(err)
	}
	if err := self.system.ConfigureNetwork(ctx, leaderPid, self.plan.Network); err != nil {
		return fail(err)
	}
	root, err := self.system.OpenRoot(leaderPid)
	if err != nil {
		return fail(err)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.supervisor = supervisor
	self.supervisorDone = supervisorDone
	self.leaderPid = leaderPid
	self.root = root
	self.state = enclaveContainerRunning
	started = true
	return nil
}

// Waits for the container's first process, polling at StartPollInterval on the clock, until StartTimeout, the
// supervisor's exit or ctx's end.
func (self *EnclaveContainer) waitLeader(ctx context.Context, supervisorDone <-chan struct{}) (int, error) {
	deadline := self.clock.After(self.settings.StartTimeout)
	for {
		leaderPid, err := self.system.Leader(self.plan)
		if err != nil {
			return 0, err
		}
		if 0 < leaderPid {
			return leaderPid, nil
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-supervisorDone:
			return 0, ErrEnclaveContainerExited
		case <-deadline:
			return 0, ErrEnclaveContainerStartTimeout
		case <-self.clock.After(self.settings.StartPollInterval):
		}
	}
}

// Asks the supervisor to stop the container, and kills the container's scope whole at StopTimeout, or once the
// supervisor exits leaving any of it behind.
func (self *EnclaveContainer) kill(supervisor EnclaveContainerProcess, supervisorDone <-chan struct{}) {
	if err := supervisor.Terminate(); err != nil && self.log.V(1).Enabled() {
		self.log.Infof("[enclave]the %s container's runtime took no stop: %s", self.plan.MachineName, err)
	}
	select {
	case <-supervisorDone:
	case <-self.clock.After(self.settings.StopTimeout):
	}
	if err := supervisor.Kill(); err != nil {
		self.log.Warningf("[enclave]the %s container could not be killed: %s", self.plan.MachineName, err)
	}
	<-supervisorDone
}

// Removes the veth's rules, logging a failure: the veth is gone with the container, so its rules match nothing.
func (self *EnclaveContainer) withdraw(ctx context.Context) {
	if err := self.firewall.WithdrawContainer(ctx, self.plan.Network); err != nil {
		self.log.Warningf("[enclave]the %s container's veth rules stay: %s", self.plan.MachineName, err)
	}
}

// Unmounts the overlay, logging a failure.
func (self *EnclaveContainer) releaseRoot() {
	if err := self.system.ReleaseRoot(self.plan); err != nil {
		self.log.Warningf("[enclave]the %s container's root stays mounted: %s", self.plan.MachineName, err)
	}
}

// Stops the container: its runtime asked to power it off and killed at StopTimeout, its veth's rules withdrawn, its
// root closed and unmounted. Its upper layer stays for a start later in the incarnation. A stopped container answers
// nil.
func (self *EnclaveContainer) Stop(ctx context.Context) error {
	supervisor, supervisorDone, root, running := func() (EnclaveContainerProcess, chan struct{}, *os.File, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.state != enclaveContainerRunning {
			return nil, nil, nil, false
		}
		self.state = enclaveContainerStopping
		return self.supervisor, self.supervisorDone, self.root, true
	}()
	if !running {
		return nil
	}
	self.kill(supervisor, supervisorDone)
	self.withdraw(ctx)
	root.Close()
	self.releaseRoot()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.supervisor = nil
	self.supervisorDone = nil
	self.leaderPid = 0
	self.root = nil
	self.state = enclaveContainerStopped
	return nil
}

// The first process's pid as the daemon sees it, while the container runs: the daemon, root outside, reads its
// namespaces, its network namespace's socket tables among them, for LSTN (C§26.4).
func (self *EnclaveContainer) LeaderPid() (int, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.state != enclaveContainerRunning {
		return 0, ErrEnclaveContainerState
	}
	return self.leaderPid, nil
}

// The running container's first process, after its supervisor's exit is checked.
func (self *EnclaveContainer) runningLeader() (int, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.state != enclaveContainerRunning {
		return 0, ErrEnclaveContainerState
	}
	select {
	case <-self.supervisorDone:
		return 0, ErrEnclaveContainerExited
	default:
	}
	return self.leaderPid, nil
}

// Runs a process inside the running container's namespaces, as spec's user, under the container's seccomp filter
// and limits from its first instruction: HARN's tool processes and SSH.md's sessions' programs. The process is
// returned started; the caller waits for it.
func (self *EnclaveContainer) Exec(ctx context.Context, spec *EnclaveContainerExec) (EnclaveContainerProcess, error) {
	if spec == nil || len(spec.Argv) == 0 || spec.Argv[0] == "" {
		return nil, fmt.Errorf("%w: no program", ErrEnclaveContainerRefused)
	}
	leaderPid, err := self.runningLeader()
	if err != nil {
		return nil, err
	}
	command, err := self.runtime.ExecCommand(self.plan, leaderPid, spec)
	if err != nil {
		return nil, err
	}
	return self.system.Run(ctx, command)
}

// Opens a listener on the running container's own loopback, in its network namespace, for the gateway (GW C§8.7):
// the socket is the daemon's, made on a thread of the daemon's that returns to the daemon's namespace, so nothing
// the agents control carries it. Only TCP on a loopback address: nothing else of the daemon's listens there.
func (self *EnclaveContainer) ListenInNamespace(network string, address string) (net.Listener, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("%w: only tcp listens in a container's namespace", ErrEnclaveContainerRefused)
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEnclaveContainerRefused, err)
	}
	if hostAddr, err := netip.ParseAddr(host); err != nil || !hostAddr.IsLoopback() {
		return nil, fmt.Errorf("%w: a listener in a container's namespace sits on its loopback", ErrEnclaveContainerRefused)
	}
	leaderPid, err := self.runningLeader()
	if err != nil {
		return nil, err
	}
	return self.system.Listen(leaderPid, network, address)
}

// A descriptor of the running container's root as its processes see it, O_PATH, for the Harness's file tools to
// open beneath with EnclaveContainerOpenInRoot, so a link an agent planted resolves inside it. The caller closes it.
func (self *EnclaveContainer) RootHandle() (*os.File, error) {
	root := func() *os.File {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.state != enclaveContainerRunning {
			return nil
		}
		return self.root
	}()
	if root == nil {
		return nil, ErrEnclaveContainerState
	}
	// a Stop closing root meanwhile fails the dup, never dups another file in its place
	return self.system.Dup(root)
}

// Whether pid, as the daemon sees it, runs inside the running container, and its pid there (EnclaveContainerScope).
func (self *EnclaveContainer) Contains(pid int) (int, bool) {
	leaderPid, err := self.runningLeader()
	if err != nil || pid <= 0 {
		return 0, false
	}
	return self.system.NamespacePid(pid, leaderPid)
}

// Whether a uid outside, a peer's, is one of the container's (EnclaveContainerScope).
func (self *EnclaveContainer) OwnsUid(uid uint32) bool {
	return self.plan.UidBase <= uid && uid-self.plan.UidBase < self.plan.UidCount
}

// The person-only edit container of §12.9: the same shape as the agents' with a user namespace of its own, the
// agents' root file system at /agents, its veth routed as the agents', and no container socket. No agent process
// enters or writes it: an edit SSH session lands in it through Exec, and nothing runs in it otherwise. Start it after
// the agents' container and stop it before.
type EnclaveEditContainer struct {
	*EnclaveContainer
}

// The edit container beside agents, stopped. args.Role and args.AgentsRootPath are set here.
func NewEnclaveEditContainer(args *EnclaveContainerArgs, agents *EnclaveContainer) (*EnclaveEditContainer, error) {
	if agents == nil || agents.plan.Role != EnclaveContainerRoleAgents {
		return nil, fmt.Errorf("%w: the edit container stands beside the agents'", ErrEnclaveContainerSettings)
	}
	editArgs := *args
	editArgs.Role = EnclaveContainerRoleEdit
	editArgs.AgentsRootPath = agents.plan.RootPath
	container, err := NewEnclaveContainer(&editArgs)
	if err != nil {
		return nil, err
	}
	return &EnclaveEditContainer{EnclaveContainer: container}, nil
}
