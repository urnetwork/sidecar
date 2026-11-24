//go:build !ios_extension && !sidecar_http

// The agents' and edit containers as data, on every leg (enclave_container.go, enclave_container_runtime.go,
// enclave_container_seccomp.go): the nspawn arguments, mounts and device list with no TEE interface and ur
// read-only; the seccomp filter run on bpf's VM for both architectures; the image's files held to the code; and the
// start, exec, listen and stop sequence on a fake system and firewall, failing closed where the boundary is not
// there. The kernel's side runs on a privileged Linux runner (enclave_container_linux_test.go).

package sidecar

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/bpf"
)

// Whether argv holds want.
func enclaveTestHas(argv []string, want string) bool {
	return slices.Contains(argv, want)
}

func TestEnclaveContainerPlan(t *testing.T) {
	settings := DefaultEnclaveContainerSettings()
	agents, err := NewEnclaveContainerPlan(settings, EnclaveContainerRoleAgents, "")
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := NewEnclaveContainerRuntime(settings)
	if err != nil {
		t.Fatal(err)
	}
	command, err := runtime.StartCommand(agents)
	if err != nil {
		t.Fatal(err)
	}
	argv := command.Argv
	nspawn := slices.Index(argv, settings.NspawnPath)
	if argv[0] != settings.SystemdRunPath || nspawn < 0 || !enclaveTestHas(argv[:nspawn], "--scope") {
		t.Fatalf("the start is not systemd-run's scope around nspawn: %v", argv)
	}
	// the scope's limits leave the daemon its share, and its devices are closed but for the basics
	for _, want := range []string{
		"--unit=ur-agents.scope", "--slice=ur-containers.slice", "--property=Delegate=yes",
		"--property=DevicePolicy=closed", "--property=MemoryMax=75%", "--property=CPUWeight=50", "--property=TasksMax=8192",
	} {
		if !enclaveTestHas(argv[:nspawn], want) {
			t.Errorf("the scope lacks %s", want)
		}
	}
	for _, want := range []string{
		"--keep-unit", "--register=no", "--settings=no", "--machine=ur-agents", "--directory=" + agents.RootPath,
		"--private-users=524288:65536", "--private-users-ownership=map", "--network-veth", "--resolv-conf=off",
		"--kill-signal=SIGRTMIN+3", "--oom-score-adjust=500",
		"--system-call-filter=~io_uring_setup io_uring_enter io_uring_register userfaultfd",
		"--bind-ro=/usr/bin/ur:/usr/local/bin/ur",
		"--bind-ro=/usr/bin/ur:" + settings.SeccompShimMountPath,
		"--bind-ro=" + agents.ResolvConfPath + ":/etc/resolv.conf",
		"--bind-ro=/run/ur/container:/run/ur",
	} {
		if !enclaveTestHas(argv[nspawn:], want) {
			t.Errorf("nspawn lacks %s: %v", want, argv[nspawn:])
		}
	}
	// the first process is the shim, which execs the init
	if tail := argv[len(argv)-4:]; !slices.Equal(tail, []string{"--", settings.SeccompShimMountPath, "--", settings.InitPath}) {
		t.Errorf("the container's first process is %v", tail)
	}
	for _, arg := range argv {
		if enclaveContainerTeePath(strings.TrimPrefix(strings.TrimPrefix(arg, "--bind="), "--bind-ro=")) {
			t.Errorf("a TEE interface in the start: %s", arg)
		}
		for _, teePath := range enclaveContainerTeePaths {
			if strings.Contains(arg, teePath) {
				t.Errorf("the start names %s: %s", teePath, arg)
			}
		}
		// ur only ever read-only
		if strings.HasPrefix(arg, "--bind="+settings.UrPath+":") {
			t.Errorf("ur bound writable: %s", arg)
		}
	}
	if len(agents.Devices) != 0 {
		t.Errorf("the agents' container takes devices by default: %v", agents.Devices)
	}
	if string(agents.Files[agents.ResolvConfPath]) != "nameserver 10.88.0.1\n" {
		t.Errorf("the resolv.conf is %q", agents.Files[agents.ResolvConfPath])
	}
	network := agents.Network
	if network.HostInterface != "ve-ur-agents" || network.ContainerInterface != "host0" ||
		network.HostPrefix.String() != "10.88.0.1/30" || network.ContainerAddress.String() != "10.88.0.2" || network.DnsPort != 53 {
		t.Errorf("the veth is %+v", network)
	}
	if agents.ScopeCgroupPath != "/sys/fs/cgroup/ur.slice/ur-containers.slice/ur-agents.scope" ||
		agents.ExecCgroupPath != agents.ScopeCgroupPath+"/ur-exec" {
		t.Errorf("the cgroups are %s and %s", agents.ScopeCgroupPath, agents.ExecCgroupPath)
	}

	// an Exec runs ur outside under the shim's name, which execs nsenter into every namespace, in a leaf of its own
	exec, err := runtime.ExecCommand(agents, 4242, &EnclaveContainerExec{Argv: []string{"bash", "-c", "make"}, Env: []string{"HOME=/root"}, Dir: "/root/work"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		settings.UrPath, "--", settings.NsenterPath, "--target", "4242",
		"--user", "--mount", "--pid", "--net", "--ipc", "--uts", "--cgroup", "--root", "--wd=/root/work",
		"--setuid", "0", "--setgid", "0", "--", "bash", "-c", "make",
	}
	if !slices.Equal(exec.Argv, want) || exec.Name != enclaveSeccompShimName || exec.CgroupPath != agents.ExecCgroupPath || !exec.CgroupLeaf {
		t.Errorf("the exec is %v as %s in %s", exec.Argv, exec.Name, exec.CgroupPath)
	}
	if !slices.Equal(exec.Env, []string{"HOME=/root", "PATH=" + settings.ExecSearchPath}) {
		t.Errorf("the exec's environment is %v", exec.Env)
	}

	// the edit container: its own user namespace and veth, the agents' root at /agents, and no container socket
	edit, err := NewEnclaveContainerPlan(settings, EnclaveContainerRoleEdit, agents.RootPath)
	if err != nil {
		t.Fatal(err)
	}
	if mount := edit.mountAt("/agents"); mount == nil || mount.Source != agents.RootPath || !mount.Idmap || mount.ReadOnly {
		t.Errorf("the edit container's /agents is %+v", mount)
	}
	if mount := edit.mountAt(agents.mountAt("/run/ur").Target); mount != nil {
		t.Errorf("the edit container takes the container socket: %+v", mount)
	}
	for _, mount := range edit.Mounts {
		if mount.Source == filepath.Dir(settings.Socket.Path) {
			t.Errorf("the edit container binds the socket's directory at %s", mount.Target)
		}
	}
	if edit.UidBase == agents.UidBase || edit.Network.HostInterface != "ve-ur-edit" || edit.Network.ContainerAddress.String() != "10.88.0.6" {
		t.Errorf("the edit container is not apart: %d %+v", edit.UidBase, edit.Network)
	}
}

func TestEnclaveContainerPlanRefusesATeeInterface(t *testing.T) {
	for _, device := range []string{"/dev/tdx_guest", "/dev/sev-guest", "/dev/sev", "/dev/tpm0", "/dev/tpmrm0", "/dev/tdx-guest"} {
		settings := DefaultEnclaveContainerSettings()
		settings.Agents.Devices = []string{device}
		if _, err := NewEnclaveContainerPlan(settings, EnclaveContainerRoleAgents, ""); !errors.Is(err, ErrEnclaveContainerSettings) {
			t.Errorf("the device %s was taken: %v", device, err)
		}
	}
	// a GPU, M15's, is bound and allowed in its scope
	settings := DefaultEnclaveContainerSettings()
	settings.Agents.Devices = []string{"/dev/nvidia0"}
	plan, err := NewEnclaveContainerPlan(settings, EnclaveContainerRoleAgents, "")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(plan.ScopeProperties, "DeviceAllow=/dev/nvidia0 rw") {
		t.Errorf("the GPU is not allowed in the scope: %v", plan.ScopeProperties)
	}
	runtime, _ := NewEnclaveContainerRuntime(settings)
	command, _ := runtime.StartCommand(plan)
	if !enclaveTestHas(command.Argv, "--bind=/dev/nvidia0") {
		t.Errorf("the GPU is not bound: %v", command.Argv)
	}
	// a mount naming one is refused whatever made it
	plan.Mounts = append(plan.Mounts, &EnclaveContainerMount{Source: "/sys/kernel/config/tsm/report", Target: "/tsm"})
	if err := plan.checkBoundary(); !errors.Is(err, ErrEnclaveContainerSettings) {
		t.Errorf("a configfs-tsm mount passed: %v", err)
	}
	plan.Mounts = plan.Mounts[:len(plan.Mounts)-1]
	plan.Mounts[0].ReadOnly = false
	if err := plan.checkBoundary(); !errors.Is(err, ErrEnclaveContainerSettings) {
		t.Errorf("ur bound writable passed: %v", err)
	}
}

func TestEnclaveContainerSettingsRefuseOverlaps(t *testing.T) {
	cases := []func(settings *EnclaveContainerSettings){
		func(settings *EnclaveContainerSettings) { settings.Edit.UidBase = settings.Agents.UidBase + 1 },
		func(settings *EnclaveContainerSettings) { settings.Edit.MachineName = settings.Agents.MachineName },
		func(settings *EnclaveContainerSettings) { settings.Edit.HostPrefix = settings.Agents.HostPrefix },
		func(settings *EnclaveContainerSettings) {
			settings.Agents.ContainerAddress = settings.Edit.ContainerAddress
		},
		func(settings *EnclaveContainerSettings) { settings.Agents.MachineName = "ur-agents-longer" },
		func(settings *EnclaveContainerSettings) { settings.Agents.MachineName = "ur_agents" },
		func(settings *EnclaveContainerSettings) { settings.RootFsPath = "relative/root" },
		func(settings *EnclaveContainerSettings) { settings.ScratchPath = "/var/lib/ur:scratch" },
		func(settings *EnclaveContainerSettings) { settings.SeccompShimMountPath = "/usr/local/lib/ur/shim" },
		func(settings *EnclaveContainerSettings) { settings.Runtime = "docker" },
		func(settings *EnclaveContainerSettings) { settings.DnsPort = 70000 },
		func(settings *EnclaveContainerSettings) { settings.StartPollInterval = 0 },
		func(settings *EnclaveContainerSettings) { settings.Socket.MountPath = "/run/ur/other.sock" },
		func(settings *EnclaveContainerSettings) { settings.Socket.SessionCount = 0 },
	}
	for i, change := range cases {
		settings := DefaultEnclaveContainerSettings()
		change(settings)
		if _, err := NewEnclaveContainerPlan(settings, EnclaveContainerRoleAgents, ""); !errors.Is(err, ErrEnclaveContainerSettings) {
			t.Errorf("case %d was taken: %v", i, err)
		}
	}
	if _, err := NewEnclaveContainerPlan(DefaultEnclaveContainerSettings(), EnclaveContainerRoleEdit, ""); !errors.Is(err, ErrEnclaveContainerSettings) {
		t.Errorf("an edit container with no agents' root was taken: %v", err)
	}
}

// A seccomp_data for bpf's VM, whose loads read big-endian words: each word written so the VM reads the value the
// kernel's native load would.
func enclaveTestSeccompData(nr uint32, arch uint32, args ...uint32) []byte {
	data := make([]byte, 64)
	binary.BigEndian.PutUint32(data[0:4], nr)
	binary.BigEndian.PutUint32(data[4:8], arch)
	for i, arg := range args {
		binary.BigEndian.PutUint32(data[16+8*i:20+8*i], arg)
	}
	return data
}

func TestEnclaveSeccompProfile(t *testing.T) {
	profile := EnclaveContainerSeccompProfile()
	allow := int(enclaveSeccompRetAllow)
	kill := int(enclaveSeccompRetKillProcess)
	eperm := int(enclaveSeccompRetErrno | enclaveSeccompErrnoEperm)
	enosys := int(enclaveSeccompRetErrno | enclaveSeccompErrnoEnosys)
	cloneNewNs := uint32(0x00020000)
	sigchld := uint32(17)
	for goarch, architecture := range enclaveSeccompArchitectures {
		program, err := EnclaveContainerSeccompProgram(profile, goarch)
		if err != nil {
			t.Fatal(err)
		}
		vm, err := bpf.NewVM(program)
		if err != nil {
			t.Fatal(err)
		}
		number := func(name string) uint32 {
			return architecture.numbers[name]
		}
		other := enclaveSeccompArchitectures["arm64"].auditArch
		if goarch == "arm64" {
			other = enclaveSeccompArchitectures["amd64"].auditArch
		}
		// read, ptrace, mount and setns on each ABI: amd64's 0, 101, 165, 308; arm64's 63, 117, 40, 268
		allowed := map[string][]uint32{"amd64": {0, 101, 165, 308}, "arm64": {63, 117, 40, 268}}[goarch]
		cases := []struct {
			data []byte
			want int
		}{
			{enclaveTestSeccompData(number("unshare"), other, enclaveSeccompCloneNewUser), kill},
			{enclaveTestSeccompData(number("unshare"), architecture.auditArch, enclaveSeccompCloneNewUser), eperm},
			{enclaveTestSeccompData(number("unshare"), architecture.auditArch, enclaveSeccompCloneNewUser|cloneNewNs), eperm},
			{enclaveTestSeccompData(number("unshare"), architecture.auditArch, cloneNewNs), allow},
			{enclaveTestSeccompData(number("clone"), architecture.auditArch, enclaveSeccompCloneNewUser|sigchld), eperm},
			{enclaveTestSeccompData(number("clone"), architecture.auditArch, sigchld), allow},
			{enclaveTestSeccompData(number("clone3"), architecture.auditArch), enosys},
			{enclaveTestSeccompData(number("io_uring_setup"), architecture.auditArch), enosys},
			{enclaveTestSeccompData(number("io_uring_enter"), architecture.auditArch), enosys},
			{enclaveTestSeccompData(number("io_uring_register"), architecture.auditArch), enosys},
		}
		for _, name := range []string{"bpf", "userfaultfd", "perf_event_open", "keyctl", "add_key", "request_key",
			"kexec_load", "kexec_file_load", "init_module", "finit_module", "delete_module", "open_by_handle_at"} {
			cases = append(cases, struct {
				data []byte
				want int
			}{enclaveTestSeccompData(number(name), architecture.auditArch), eperm})
		}
		for _, nr := range allowed {
			cases = append(cases, struct {
				data []byte
				want int
			}{enclaveTestSeccompData(nr, architecture.auditArch, enclaveSeccompCloneNewUser), allow})
		}
		if architecture.x32 {
			// x32's unshare, its number with the x32 bit
			cases = append(cases, struct {
				data []byte
				want int
			}{enclaveTestSeccompData(enclaveSeccompX32SyscallBit|number("unshare"), architecture.auditArch), kill})
		}
		for i, c := range cases {
			got, err := vm.Run(c.data)
			if err != nil || got != c.want {
				t.Errorf("%s case %d: %#x %v, want %#x", goarch, i, got, err, c.want)
			}
		}
	}
	if _, err := EnclaveContainerSeccompProgram(profile, "riscv64"); err == nil {
		t.Error("a filter was made for an architecture with no numbers")
	}
	// the OCI form names the same calls and conditions
	oci, err := profile.OciJson()
	if err != nil {
		t.Fatal(err)
	}
	decoded := &enclaveSeccompOci{}
	if err := json.Unmarshal(oci, decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.DefaultAction != "SCMP_ACT_ALLOW" || len(decoded.Syscalls) != len(profile.Rules) {
		t.Fatalf("the OCI profile is %s", oci)
	}
	unshare := decoded.Syscalls[0]
	if unshare.Names[0] != "unshare" || unshare.ErrnoRet != 1 || len(unshare.Args) != 1 || unshare.Args[0].Op != "SCMP_CMP_MASKED_EQ" ||
		unshare.Args[0].Value != uint64(enclaveSeccompCloneNewUser) {
		t.Errorf("the OCI unshare rule is %+v", unshare)
	}
}

// Rewrites enclave/container/ from the code instead of comparing, for a change of the defaults.
const enclaveContainerFilesRegenerate = "SIDECAR_REGENERATE_ENCLAVE_CONTAINER"

// The image's copy of the defaults (enclave/container/) is the code's: the nspawn settings, the seccomp profile and
// the kernel settings, and nothing else.
func TestEnclaveContainerFilesAreCurrent(t *testing.T) {
	files, err := EnclaveContainerFiles(DefaultEnclaveContainerSettings())
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join("enclave", "container")
	if os.Getenv(enclaveContainerFilesRegenerate) != "" {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
		for name, content := range files {
			if err := os.WriteFile(filepath.Join(directory, name), content, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("%s: %v; regenerate with %s=1", directory, err, enclaveContainerFilesRegenerate)
	}
	for _, entry := range entries {
		if _, ok := files[entry.Name()]; !ok {
			t.Errorf("%s holds %s, which the code does not make", directory, entry.Name())
		}
	}
	for name, content := range files {
		onDisk, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil || !bytes.Equal(onDisk, content) {
			t.Errorf("%s is not the code's: regenerate with %s=1 go test -run '^TestEnclaveContainerFilesAreCurrent$'", name, enclaveContainerFilesRegenerate)
		}
	}
}

func TestEnclaveContainerRuntimeRunsc(t *testing.T) {
	settings := DefaultEnclaveContainerSettings()
	settings.Runtime = EnclaveContainerRuntimeRunsc
	plan, err := NewEnclaveContainerPlan(settings, EnclaveContainerRoleAgents, "")
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := NewEnclaveContainerRuntime(settings)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Prepare(plan); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.ToSlash(filepath.Join(plan.StatePath, "bundle", "config.json"))
	config := map[string]any{}
	if err := json.Unmarshal(plan.Files[configPath], &config); err != nil {
		t.Fatalf("the bundle's config: %v", err)
	}
	linux := config["linux"].(map[string]any)
	mapping := linux["uidMappings"].([]any)[0].(map[string]any)
	if mapping["hostID"].(float64) != float64(plan.UidBase) || mapping["size"].(float64) != float64(plan.UidCount) {
		t.Errorf("the bundle maps %v", mapping)
	}
	if linux["seccomp"] == nil || config["root"].(map[string]any)["path"] != plan.RootPath {
		t.Errorf("the bundle lacks the filter or the root")
	}
	urReadOnly := false
	for _, mount := range config["mounts"].([]any) {
		mount := mount.(map[string]any)
		for _, teePath := range enclaveContainerTeePaths {
			if strings.HasPrefix(mount["source"].(string), teePath) {
				t.Errorf("the bundle mounts %s", mount["source"])
			}
		}
		if mount["source"] == settings.UrPath {
			urReadOnly = slices.Contains(mount["options"].([]any), any("ro"))
		}
	}
	if !urReadOnly {
		t.Error("the bundle's ur is not read-only")
	}
	command, err := runtime.StartCommand(plan)
	if err != nil {
		t.Fatal(err)
	}
	if !enclaveTestHas(command.Argv, "--oci-seccomp") || !enclaveTestHas(command.Argv, "--bundle="+filepath.ToSlash(filepath.Join(plan.StatePath, "bundle"))) {
		t.Errorf("runsc's start is %v", command.Argv)
	}
	settings.Agents.Devices = []string{"/dev/nvidia0"}
	gpuPlan, err := NewEnclaveContainerPlan(settings, EnclaveContainerRoleAgents, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Prepare(gpuPlan); !errors.Is(err, ErrEnclaveContainerSettings) {
		t.Errorf("runsc took a GPU: %v", err)
	}
}

// A clock whose timers fire at once for the durations a test names and never for the rest.
type enclaveContainerTestClock struct {
	stateLock sync.Mutex
	firing    map[time.Duration]bool
}

func (self *enclaveContainerTestClock) Now() time.Time {
	return time.Unix(0, 0)
}

func (self *enclaveContainerTestClock) After(timeout time.Duration) <-chan time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	fired := make(chan time.Time, 1)
	if self.firing[timeout] {
		fired <- time.Unix(0, 0)
	}
	return fired
}

func (self *enclaveContainerTestClock) AfterFunc(timeout time.Duration, function func()) func() bool {
	return func() bool { return false }
}

// A process of the fake system.
type enclaveContainerTestProcess struct {
	pid       int
	system    *enclaveContainerTestSystem
	done      chan struct{}
	doneOnce  sync.Once
	terminate bool
}

func (self *enclaveContainerTestProcess) exit() {
	self.doneOnce.Do(func() { close(self.done) })
}

func (self *enclaveContainerTestProcess) Pid() int {
	return self.pid
}

func (self *enclaveContainerTestProcess) Wait() (int, error) {
	<-self.done
	return 0, nil
}

func (self *enclaveContainerTestProcess) Signal(signal os.Signal) error {
	self.system.note("signal")
	return nil
}

func (self *enclaveContainerTestProcess) Terminate() error {
	self.system.note("terminate")
	if self.terminate {
		self.exit()
	}
	return nil
}

func (self *enclaveContainerTestProcess) Kill() error {
	self.system.note("kill")
	self.exit()
	return nil
}

// A system that does nothing but note what it was asked, in order.
type enclaveContainerTestSystem struct {
	t         *testing.T
	stateLock sync.Mutex
	events    []string
	kernelErr error
	// the polls before the first process appears
	leaderPolls  int
	configureErr error
	// whether the supervisor exits at a terminate
	terminates bool
	supervisor *enclaveContainerTestProcess
	runs       []*EnclaveContainerCommand
	listens    []string
}

func (self *enclaveContainerTestSystem) note(event string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.events = append(self.events, event)
}

func (self *enclaveContainerTestSystem) noted() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.events)
}

func (self *enclaveContainerTestSystem) CheckKernel() error {
	self.note("kernel")
	return self.kernelErr
}

func (self *enclaveContainerTestSystem) PrepareRoot(ctx context.Context, plan *EnclaveContainerPlan) error {
	self.note("root")
	return nil
}

func (self *enclaveContainerTestSystem) ReleaseRoot(plan *EnclaveContainerPlan) error {
	self.note("release")
	return nil
}

func (self *enclaveContainerTestSystem) Start(ctx context.Context, command *EnclaveContainerCommand) (EnclaveContainerProcess, error) {
	self.note("start")
	process := &enclaveContainerTestProcess{pid: 10, system: self, done: make(chan struct{}), terminate: self.terminates}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.supervisor = process
	return process, nil
}

func (self *enclaveContainerTestSystem) Leader(plan *EnclaveContainerPlan) (int, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if 0 < self.leaderPolls {
		self.leaderPolls -= 1
		return 0, nil
	}
	self.events = append(self.events, "leader")
	return 100, nil
}

func (self *enclaveContainerTestSystem) PrepareExecCgroup(plan *EnclaveContainerPlan) error {
	self.note("cgroup")
	return nil
}

func (self *enclaveContainerTestSystem) ConfigureNetwork(ctx context.Context, leaderPid int, network *EnclaveContainerNetwork) error {
	self.note("network")
	return self.configureErr
}

func (self *enclaveContainerTestSystem) OpenRoot(leaderPid int) (*os.File, error) {
	self.note("open root")
	return os.Open(self.t.TempDir())
}

func (self *enclaveContainerTestSystem) Dup(file *os.File) (*os.File, error) {
	return os.Open(file.Name())
}

func (self *enclaveContainerTestSystem) Run(ctx context.Context, command *EnclaveContainerCommand) (EnclaveContainerProcess, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.runs = append(self.runs, command)
	return &enclaveContainerTestProcess{pid: 20, system: self, done: make(chan struct{})}, nil
}

func (self *enclaveContainerTestSystem) Listen(leaderPid int, network string, address string) (net.Listener, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.listens = append(self.listens, address)
	return nil, nil
}

func (self *enclaveContainerTestSystem) NamespacePid(pid int, leaderPid int) (int, bool) {
	return 0, false
}

// A firewall that notes what it was asked, in the system's order.
type enclaveContainerTestFirewall struct {
	system   *enclaveContainerTestSystem
	admitErr error
}

func (self *enclaveContainerTestFirewall) AdmitContainer(ctx context.Context, network *EnclaveContainerNetwork) error {
	self.system.note("admit " + network.HostInterface)
	return self.admitErr
}

func (self *enclaveContainerTestFirewall) WithdrawContainer(ctx context.Context, network *EnclaveContainerNetwork) error {
	self.system.note("withdraw " + network.HostInterface)
	return nil
}

// A container on a fake system and firewall, its leader appearing at the third poll.
func newEnclaveContainerTest(t *testing.T, firing ...time.Duration) (*EnclaveContainer, *enclaveContainerTestSystem, *enclaveContainerTestFirewall) {
	settings := DefaultEnclaveContainerSettings()
	clock := &enclaveContainerTestClock{firing: map[time.Duration]bool{}}
	for _, timeout := range firing {
		clock.firing[timeout] = true
	}
	system := &enclaveContainerTestSystem{t: t, leaderPolls: 2, terminates: true}
	firewall := &enclaveContainerTestFirewall{system: system}
	container, err := NewEnclaveContainer(&EnclaveContainerArgs{
		Settings: settings, Role: EnclaveContainerRoleAgents, System: system, Firewall: firewall, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	return container, system, firewall
}

// The order of a start and a stop, and the hooks between: the veth admitted before the runtime starts, so it carries
// no packet before its rules; the Exec cgroup made once the scope exists; an Exec through the shim; a listener only on
// the container's loopback; the root handle a descriptor of its own.
func TestEnclaveContainerStartsAndStopsInOrder(t *testing.T) {
	settings := DefaultEnclaveContainerSettings()
	container, system, _ := newEnclaveContainerTest(t, settings.StartPollInterval)
	if _, err := container.Exec(context.Background(), &EnclaveContainerExec{Argv: []string{"true"}}); !errors.Is(err, ErrEnclaveContainerState) {
		t.Errorf("a stopped container ran an exec: %v", err)
	}
	if err := container.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []string{"kernel", "root", "admit ve-ur-agents", "start", "leader", "cgroup", "network", "open root"}
	if got := system.noted(); !slices.Equal(got, want) {
		t.Fatalf("the start ran %v, want %v", got, want)
	}
	if err := container.Start(context.Background()); !errors.Is(err, ErrEnclaveContainerState) {
		t.Errorf("a second start: %v", err)
	}
	if leaderPid, err := container.LeaderPid(); err != nil || leaderPid != 100 {
		t.Errorf("the leader is %d, %v", leaderPid, err)
	}

	process, err := container.Exec(context.Background(), &EnclaveContainerExec{Argv: []string{"/usr/bin/gdb", "-p", "7"}, User: "1000:1000"})
	if err != nil || process.Pid() != 20 {
		t.Fatalf("the exec: %v", err)
	}
	run := system.runs[0]
	if run.Name != enclaveSeccompShimName || run.Argv[0] != settings.UrPath || !enclaveTestHas(run.Argv, "100") ||
		!enclaveTestHas(run.Argv, "1000") || run.Argv[len(run.Argv)-1] != "7" {
		t.Errorf("the exec ran %v as %s", run.Argv, run.Name)
	}
	for _, refused := range []*EnclaveContainerExec{
		{},
		{Argv: []string{""}},
		{Argv: []string{"true"}, Env: []string{"NOEQUALS"}},
		{Argv: []string{"true"}, User: "agent"},
		{Argv: []string{"true"}, Dir: "relative"},
	} {
		if _, err := container.Exec(context.Background(), refused); !errors.Is(err, ErrEnclaveContainerRefused) {
			t.Errorf("an exec %+v was taken: %v", refused, err)
		}
	}

	if _, err := container.ListenInNamespace("tcp", "127.0.0.1:0"); err != nil {
		t.Errorf("a loopback listener: %v", err)
	}
	for _, address := range []string{"10.88.0.2:8080", "0.0.0.0:8080", "[::]:8080"} {
		if _, err := container.ListenInNamespace("tcp", address); !errors.Is(err, ErrEnclaveContainerRefused) {
			t.Errorf("a listener at %s was taken: %v", address, err)
		}
	}
	if _, err := container.ListenInNamespace("udp", "127.0.0.1:53"); !errors.Is(err, ErrEnclaveContainerRefused) {
		t.Errorf("a udp listener was taken: %v", err)
	}
	if len(system.listens) != 1 {
		t.Errorf("the system listened at %v", system.listens)
	}
	root, err := container.RootHandle()
	if err != nil {
		t.Fatal(err)
	}
	root.Close()

	if err := container.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	stopped := system.noted()[len(want):]
	if !slices.Equal(stopped, []string{"terminate", "kill", "withdraw ve-ur-agents", "release"}) {
		t.Errorf("the stop ran %v", stopped)
	}
	if _, err := container.RootHandle(); !errors.Is(err, ErrEnclaveContainerState) {
		t.Errorf("a stopped container's root: %v", err)
	}
}

// Every way a start fails leaves nothing up: no firewall starts nothing at all; a kernel without the boundary, a
// firewall that refuses, a leader that never comes and a network that cannot be set each undo what started.
func TestEnclaveContainerStartFailsClosed(t *testing.T) {
	settings := DefaultEnclaveContainerSettings()

	system := &enclaveContainerTestSystem{t: t}
	container, err := NewEnclaveContainer(&EnclaveContainerArgs{Settings: settings, Role: EnclaveContainerRoleAgents, System: system})
	if err != nil {
		t.Fatal(err)
	}
	if err := container.Start(context.Background()); !errors.Is(err, ErrEnclaveContainerNoFirewall) {
		t.Errorf("a start with no firewall: %v", err)
	}
	if events := system.noted(); len(events) != 0 {
		t.Errorf("a start with no firewall ran %v", events)
	}
	noSystem, err := NewEnclaveContainer(&EnclaveContainerArgs{Settings: settings, Role: EnclaveContainerRoleAgents})
	if err != nil {
		t.Fatal(err)
	}
	if enclaveContainerBuildSystem == nil {
		if err := noSystem.Start(context.Background()); !errors.Is(err, ErrEnclaveContainerUnsupported) {
			t.Errorf("a start with no system: %v", err)
		}
	}

	container, system, _ = newEnclaveContainerTest(t)
	system.kernelErr = ErrEnclaveContainerKernel
	if err := container.Start(context.Background()); !errors.Is(err, ErrEnclaveContainerKernel) {
		t.Errorf("a start on a kernel without the boundary: %v", err)
	}
	if events := system.noted(); !slices.Equal(events, []string{"kernel"}) {
		t.Errorf("a start on a kernel without the boundary ran %v", events)
	}

	container, system, firewall := newEnclaveContainerTest(t)
	firewall.admitErr = errors.New("nft refused")
	if err := container.Start(context.Background()); !errors.Is(err, ErrEnclaveContainerNoFirewall) {
		t.Errorf("a start the firewall refused: %v", err)
	}
	if events := system.noted(); !slices.Equal(events, []string{"kernel", "root", "admit ve-ur-agents", "release"}) {
		t.Errorf("a start the firewall refused ran %v", events)
	}

	// the leader never comes: the start times out, and the supervisor, which ignores its terminate, is killed
	container, system, _ = newEnclaveContainerTest(t, settings.StartTimeout, settings.StopTimeout)
	system.leaderPolls = 1 << 30
	system.terminates = false
	if err := container.Start(context.Background()); !errors.Is(err, ErrEnclaveContainerStartTimeout) {
		t.Errorf("a start whose leader never came: %v", err)
	}
	if events := system.noted(); !slices.Equal(events, []string{"kernel", "root", "admit ve-ur-agents", "start", "terminate", "kill", "withdraw ve-ur-agents", "release"}) {
		t.Errorf("a start whose leader never came ran %v", events)
	}

	container, system, _ = newEnclaveContainerTest(t, settings.StartPollInterval)
	system.configureErr = errors.New("no veth")
	if err := container.Start(context.Background()); err == nil {
		t.Error("a start whose network failed passed")
	}
	if events := system.noted(); !slices.Equal(events, []string{"kernel", "root", "admit ve-ur-agents", "start", "leader", "cgroup", "network", "terminate", "kill", "withdraw ve-ur-agents", "release"}) {
		t.Errorf("a start whose network failed ran %v", events)
	}
	// and it may start again
	system.configureErr = nil
	if err := container.Start(context.Background()); err != nil {
		t.Errorf("a start after a failed one: %v", err)
	}
}

// The edit container stands beside the agents': it takes their root at /agents, and none of their socket.
func TestEnclaveEditContainerStandsBesideTheAgents(t *testing.T) {
	agents, system, firewall := newEnclaveContainerTest(t)
	edit, err := NewEnclaveEditContainer(&EnclaveContainerArgs{System: system, Firewall: firewall}, agents)
	if err != nil {
		t.Fatal(err)
	}
	plan := edit.Plan()
	if plan.Role != EnclaveContainerRoleEdit || plan.mountAt("/agents").Source != agents.Plan().RootPath {
		t.Errorf("the edit container is %s with /agents %+v", plan.Role, plan.mountAt("/agents"))
	}
	if _, err := NewEnclaveEditContainer(&EnclaveContainerArgs{System: system}, edit.EnclaveContainer); !errors.Is(err, ErrEnclaveContainerSettings) {
		t.Errorf("an edit container beside an edit container: %v", err)
	}
}
