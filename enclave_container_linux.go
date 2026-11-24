//go:build linux && ur_enclave

// The enclave's system for its containers (enclave_container.go's EnclaveContainerSystem), built only into ur's
// enclave build (the tag ur_enclave, ENC.md's build legs):
//
//	shim        ur run under the seccomp shim's name (enclaveSeccompShimName) installs the containers' filter on
//	            every thread (SECCOMP_FILTER_FLAG_TSYNC) and execs what follows "--", from this package's init, so
//	            nothing else of ur runs first: the container's first process is the shim, which execs systemd, and
//	            every Exec runs the shim outside, which execs nsenter, so the filter holds before the process enters
//	            the container and no process in it runs without the filter. A filter that cannot be installed execs
//	            nothing
//	kernel      unprivileged BPF and io_uring off are read from /proc/sys before anything starts
//	root        the overlay of the image's root and the scratch volume's upper layer, mounted at the plan's root;
//	            RootHandle's descriptor is /proc/<first process>/root, O_PATH, the root as the container's
//	            processes see it, and EnclaveContainerOpenInRoot opens beneath it with openat2's RESOLVE_IN_ROOT
//	            and RESOLVE_NO_MAGICLINKS, so a link an agent planted resolves inside
//	network     rtnetlink from the daemon itself, never a spawned ip: the veth's host end takes its address, strict
//	            reverse-path filtering (a source outside its prefix is dropped), forwarding and no IPv6; the
//	            container end its address and default route, set on a thread of the daemon's own moved into the
//	            container's network namespace and moved back, as ListenInNamespace's listener is made
//	cgroups     each Exec starts in a leaf of its own beneath the scope's ur-exec cgroup (CLONE_INTO_CGROUP), and a
//	            kill writes cgroup.kill, so a program that forked away inside the container ends with it; the
//	            supervisor's kill ends the whole scope
//	peers       the container socket's caller by SO_PEERCRED, its pid and ids as the daemon's namespaces see them,
//	            and whether it runs in the container's PID namespace, read from /proc/<pid>/ns/pid
//
// It needs systemd-run, systemd-nspawn and util-linux's nsenter in the image (ENC-M14-16), cgroup v2 with
// cgroup.kill (Linux 5.14), openat2 (5.6), idmapped mounts of the overlay (map ownership) and the kernel settings
// enclave/container/'s sysctl file sets.

package sidecar

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// Takes the process over when it runs as the seccomp shim, before anything else of ur runs; otherwise gives the
// containers this leg's system and the socket its peer reader.
func init() {
	if filepath.Base(os.Args[0]) == enclaveSeccompShimName {
		// returns only when it could not exec, the filter installed or not
		os.Exit(enclaveSeccompShimMain(os.Args[1:]))
	}
	enclaveContainerBuildSystem = func() EnclaveContainerSystem {
		return newEnclaveContainerLinuxSystem()
	}
	enclaveContainerBuildPeer = enclaveContainerPeerOfConn
}

// The shim's exit codes, as a shell's for a command that could not run.
const (
	enclaveSeccompShimUsage  = 2
	enclaveSeccompShimFailed = 126
)

// The shim: `<shim> -- /absolute/program [args...]` installs the containers' filter, then execs the program with
// this process's environment. Returns only on failure, having execed nothing.
func enclaveSeccompShimMain(args []string) int {
	if len(args) < 2 || args[0] != "--" || !filepath.IsAbs(args[1]) {
		fmt.Fprintf(os.Stderr, "%s: usage: %s -- /absolute/program [args...]\n", enclaveSeccompShimName, enclaveSeccompShimName)
		return enclaveSeccompShimUsage
	}
	if err := enclaveSeccompInstall(EnclaveContainerSeccompProfile()); err != nil {
		fmt.Fprintf(os.Stderr, "%s: the filter did not install, so nothing runs: %s\n", enclaveSeccompShimName, err)
		return enclaveSeccompShimFailed
	}
	err := unix.Exec(args[1], args[1:], os.Environ())
	fmt.Fprintf(os.Stderr, "%s: %s\n", enclaveSeccompShimName, err)
	return enclaveSeccompShimFailed
}

// Installs profile's filter for this architecture on every thread of the process. Without no_new_privs it needs
// CAP_SYS_ADMIN in the caller's user namespace, which the daemon's root and a container's root both hold, so setuid
// programs inside keep working.
func enclaveSeccompInstall(profile *EnclaveSeccompProfile) error {
	program, err := EnclaveContainerSeccompProgram(profile, runtime.GOARCH)
	if err != nil {
		return err
	}
	raw, err := bpf.Assemble(program)
	if err != nil {
		return err
	}
	filters := make([]unix.SockFilter, len(raw))
	for i, instruction := range raw {
		filters[i] = unix.SockFilter{Code: instruction.Op, Jt: instruction.Jt, Jf: instruction.Jf, K: instruction.K}
	}
	fprog := unix.SockFprog{Len: uint16(len(filters)), Filter: &filters[0]}
	// with TSYNC a thread that cannot take the filter is named by the return value, not errno
	result, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC,
		uintptr(unsafe.Pointer(&fprog)))
	runtime.KeepAlive(filters)
	if errno != 0 {
		return errno
	}
	if result != 0 {
		return fmt.Errorf("thread %d could not take the filter", result)
	}
	return nil
}

// Opens name beneath root, a container's root (RootHandle), as openat2 with RESOLVE_IN_ROOT resolves it: an absolute
// link, a .. and a link to one all stay inside, and a /proc magic link is refused, so a link an agent planted
// resolves inside the container whatever it names. flags are open(2)'s; O_CLOEXEC is added.
func EnclaveContainerOpenInRoot(root *os.File, name string, flags int, mode uint32) (*os.File, error) {
	raw, err := root.SyscallConn()
	if err != nil {
		return nil, err
	}
	fd := -1
	openErr := error(nil)
	if err := raw.Control(func(rootFd uintptr) {
		fd, openErr = unix.Openat2(int(rootFd), name, &unix.OpenHow{
			Flags:   uint64(flags) | unix.O_CLOEXEC,
			Mode:    uint64(mode),
			Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
		})
	}); err != nil {
		return nil, err
	}
	if openErr != nil {
		return nil, &os.PathError{Op: "openat2", Path: name, Err: openErr}
	}
	return os.NewFile(uintptr(fd), name), nil
}

// The enclave's system.
type enclaveContainerLinuxSystem struct {
	// how deep the daemon's own PID namespace is, by /proc/self/status's NSpid: a container's first process is one
	// deeper, and pid 1 there
	nspidDepth int
	// each Exec's leaf name
	stateLock sync.Mutex
	execCount uint64
}

// The system, its own PID namespace depth read now.
func newEnclaveContainerLinuxSystem() *enclaveContainerLinuxSystem {
	depth := 1
	if nspids, err := enclaveContainerNspids(os.Getpid()); err == nil && 0 < len(nspids) {
		depth = len(nspids)
	}
	return &enclaveContainerLinuxSystem{nspidDepth: depth}
}

// A pid's NSpid line, its pid in each PID namespace from the reader's down to its own.
func enclaveContainerNspids(pid int) ([]int, error) {
	file, err := os.Open("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), ":")
		if !ok || key != "NSpid" {
			continue
		}
		nspids := []int{}
		for _, field := range strings.Fields(value) {
			nspid, err := strconv.Atoi(field)
			if err != nil {
				return nil, err
			}
			nspids = append(nspids, nspid)
		}
		return nspids, nil
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return nil, ErrProcessUnknown
}

// One kernel setting's value, and whether the kernel has it.
func enclaveContainerSysctl(name string) (string, bool, error) {
	value, err := os.ReadFile(filepath.Join("/proc/sys", filepath.FromSlash(strings.ReplaceAll(name, ".", "/"))))
	if errors.Is(err, fs.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return strings.TrimSpace(string(value)), true, nil
}

// Reads the kernel's switches: unprivileged BPF off, and io_uring off where the kernel has the setting.
func (self *enclaveContainerLinuxSystem) CheckKernel() error {
	bpfDisabled, present, err := enclaveContainerSysctl("kernel.unprivileged_bpf_disabled")
	if err != nil || !present || (bpfDisabled != "1" && bpfDisabled != "2") {
		return fmt.Errorf("%w: kernel.unprivileged_bpf_disabled is not 1 or 2", ErrEnclaveContainerKernel)
	}
	ioUringDisabled, present, err := enclaveContainerSysctl("kernel.io_uring_disabled")
	// a kernel without the setting answers io_uring by the filter alone
	if err != nil || (present && ioUringDisabled != "2") {
		return fmt.Errorf("%w: kernel.io_uring_disabled is not 2", ErrEnclaveContainerKernel)
	}
	return nil
}

// Whether path is a mount point: its device differs from its parent's.
func enclaveContainerMounted(path string) (bool, error) {
	var stat unix.Stat_t
	if err := unix.Stat(path, &stat); err != nil {
		return false, err
	}
	var parentStat unix.Stat_t
	if err := unix.Stat(filepath.Dir(path), &parentStat); err != nil {
		return false, err
	}
	return stat.Dev != parentStat.Dev, nil
}

// Makes the container's directories and files and mounts the overlay of the image's root and the scratch volume's
// upper layer, unless one is mounted there already.
func (self *enclaveContainerLinuxSystem) PrepareRoot(ctx context.Context, plan *EnclaveContainerPlan) error {
	if info, err := os.Stat(plan.LowerPath); err != nil || !info.IsDir() {
		return fmt.Errorf("%w: the image's root %s", ErrEnclaveContainerKernel, plan.LowerPath)
	}
	if err := os.MkdirAll(plan.StatePath, 0o700); err != nil {
		return err
	}
	for _, directory := range []string{plan.UpperPath, plan.RootPath} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(plan.WorkPath, 0o700); err != nil {
		return err
	}
	for name, content := range plan.Files {
		if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
			return err
		}
		// read inside the container through a read-only bind by an unmapped owner: world-readable
		if err := os.WriteFile(name, content, 0o644); err != nil {
			return err
		}
		if err := os.Chmod(name, 0o644); err != nil {
			return err
		}
	}
	mounted, err := enclaveContainerMounted(plan.RootPath)
	if err != nil {
		return err
	}
	if mounted {
		return nil
	}
	options := "lowerdir=" + plan.LowerPath + ",upperdir=" + plan.UpperPath + ",workdir=" + plan.WorkPath
	return unix.Mount("overlay", plan.RootPath, "overlay", 0, options)
}

// Detaches the overlay; one not mounted is no error.
func (self *enclaveContainerLinuxSystem) ReleaseRoot(plan *EnclaveContainerPlan) error {
	if err := unix.Unmount(plan.RootPath, unix.MNT_DETACH); err != nil && !errors.Is(err, unix.EINVAL) {
		return err
	}
	return nil
}

// A process the system started.
type enclaveContainerLinuxProcess struct {
	cmd *exec.Cmd
	// the cgroup a kill ends whole, empty for the process alone
	cgroupPath string
	// whether cgroupPath is this process's own leaf, removed once it exits
	cgroupLeaf bool
}

// The process's pid in the daemon's namespace.
func (self *enclaveContainerLinuxProcess) Pid() int {
	return self.cmd.Process.Pid
}

// Waits for the process, then removes its own leaf, and answers its exit code.
func (self *enclaveContainerLinuxProcess) Wait() (int, error) {
	err := self.cmd.Wait()
	if self.cgroupLeaf {
		// empty once its processes are gone; one that forked away and lives keeps it, and Kill ends them
		os.Remove(self.cgroupPath)
	}
	if self.cmd.ProcessState == nil {
		return -1, err
	}
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		return -1, err
	}
	return self.cmd.ProcessState.ExitCode(), nil
}

// Signals the process's group.
func (self *enclaveContainerLinuxProcess) Signal(signal os.Signal) error {
	sig, ok := signal.(syscall.Signal)
	if !ok {
		return fmt.Errorf("%w: not a system signal", ErrEnclaveContainerRefused)
	}
	// its group: the shim's nsenter and the program it started inside
	return unix.Kill(-self.cmd.Process.Pid, sig)
}

// Sends the process SIGTERM.
func (self *enclaveContainerLinuxProcess) Terminate() error {
	return self.cmd.Process.Signal(unix.SIGTERM)
}

// Writes its cgroup's cgroup.kill, then kills the process itself.
func (self *enclaveContainerLinuxProcess) Kill() error {
	errs := []error{}
	if self.cgroupPath != "" {
		err := os.WriteFile(filepath.Join(self.cgroupPath, "cgroup.kill"), []byte("1"), 0)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	if err := self.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// Starts command with its own process group, a parent-death kill and, for a leaf, in a cgroup of its own.
func (self *enclaveContainerLinuxSystem) run(command *EnclaveContainerCommand) (EnclaveContainerProcess, error) {
	if len(command.Argv) == 0 {
		return nil, fmt.Errorf("%w: no program", ErrEnclaveContainerRefused)
	}
	cmd := exec.Command(command.Argv[0], command.Argv[1:]...)
	if command.Name != "" {
		cmd.Args[0] = command.Name
	}
	cmd.Env = command.Env
	cmd.Dir = "/"
	cmd.Stdin = command.Stdin
	cmd.Stdout = command.Stdout
	cmd.Stderr = command.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	process := &enclaveContainerLinuxProcess{cmd: cmd, cgroupPath: command.CgroupPath}
	if command.CgroupLeaf && command.CgroupPath != "" {
		leaf := func() string {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.execCount += 1
			return filepath.Join(command.CgroupPath, "exec-"+strconv.FormatUint(self.execCount, 10))
		}()
		if err := os.Mkdir(leaf, 0o755); err != nil {
			return nil, err
		}
		cgroup, err := unix.Open(leaf, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			os.Remove(leaf)
			return nil, err
		}
		defer unix.Close(cgroup)
		cmd.SysProcAttr.UseCgroupFD = true
		cmd.SysProcAttr.CgroupFD = cgroup
		process.cgroupPath = leaf
		process.cgroupLeaf = true
	}
	if err := cmd.Start(); err != nil {
		if process.cgroupLeaf {
			os.Remove(process.cgroupPath)
		}
		return nil, err
	}
	return process, nil
}

// Starts the runtime's supervisor.
func (self *enclaveContainerLinuxSystem) Start(ctx context.Context, command *EnclaveContainerCommand) (EnclaveContainerProcess, error) {
	return self.run(command)
}

// Starts an Exec's shim in a leaf of its own.
func (self *enclaveContainerLinuxSystem) Run(ctx context.Context, command *EnclaveContainerCommand) (EnclaveContainerProcess, error) {
	return self.run(command)
}

// The container's first process: the process of the scope's tree one PID namespace deeper than the daemon's, pid 1
// there. A nested namespace an agent made inside is deeper still, and an Exec's process is not pid 1, so neither is
// taken for it.
func (self *enclaveContainerLinuxSystem) Leader(plan *EnclaveContainerPlan) (int, error) {
	leaderPid := 0
	err := filepath.WalkDir(plan.ScopeCgroupPath, func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return fs.SkipAll
			}
			return err
		}
		if !entry.IsDir() {
			return nil
		}
		procs, err := os.ReadFile(filepath.Join(name, "cgroup.procs"))
		if err != nil {
			// a cgroup removed under the walk
			return nil
		}
		for _, field := range strings.Fields(string(procs)) {
			pid, err := strconv.Atoi(field)
			if err != nil {
				continue
			}
			nspids, err := enclaveContainerNspids(pid)
			if err == nil && len(nspids) == self.nspidDepth+1 && nspids[len(nspids)-1] == 1 {
				leaderPid = pid
				return fs.SkipAll
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return leaderPid, nil
}

// Makes the scope's ur-exec cgroup, which may stand from an earlier start.
func (self *enclaveContainerLinuxSystem) PrepareExecCgroup(plan *EnclaveContainerPlan) error {
	if err := os.Mkdir(plan.ExecCgroupPath, 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	return nil
}

// Writes one kernel setting of the calling thread's network namespace.
func enclaveContainerWriteSysctl(name string, value string) error {
	return os.WriteFile(filepath.Join("/proc/sys", filepath.FromSlash(name)), []byte(value), 0)
}

// Sets the veth's host end's settings, address and link up in the daemon's namespace, then its container end's
// address, link and default route from a thread moved into the container's namespace.
func (self *enclaveContainerLinuxSystem) ConfigureNetwork(ctx context.Context, leaderPid int, network *EnclaveContainerNetwork) error {
	// the host end, in the daemon's namespace
	hostInterface, err := net.InterfaceByName(network.HostInterface)
	if err != nil {
		return fmt.Errorf("the veth's host end: %w", err)
	}
	for _, setting := range [][2]string{
		// a source the prefix does not route back through this end is dropped (§11.10)
		{"net/ipv4/conf/" + network.HostInterface + "/rp_filter", "1"},
		// the container's packets go on through ur tun and the daemon's rules
		{"net/ipv4/conf/" + network.HostInterface + "/forwarding", "1"},
		{"net/ipv6/conf/" + network.HostInterface + "/disable_ipv6", "1"},
	} {
		if err := enclaveContainerWriteSysctl(setting[0], setting[1]); err != nil {
			return err
		}
	}
	if err := enclaveNetlinkAddAddress(hostInterface.Index, network.HostPrefix); err != nil {
		return err
	}
	if err := enclaveNetlinkSetUp(hostInterface.Index); err != nil {
		return err
	}
	// the container end, from a thread of the daemon's moved into the container's namespace and back
	return enclaveContainerInNetns(leaderPid, func() error {
		containerInterface, err := net.InterfaceByName(network.ContainerInterface)
		if err != nil {
			return fmt.Errorf("the veth's container end: %w", err)
		}
		prefix := netip.PrefixFrom(network.ContainerAddress, network.HostPrefix.Bits())
		if err := enclaveNetlinkAddAddress(containerInterface.Index, prefix); err != nil {
			return err
		}
		if err := enclaveNetlinkSetUp(containerInterface.Index); err != nil {
			return err
		}
		return enclaveNetlinkAddDefaultRoute(containerInterface.Index, network.HostPrefix.Addr())
	})
}

// Runs work on a thread of its own moved into leaderPid's network namespace, which returns to the daemon's after: a
// thread that cannot return ends with its goroutine and serves nothing else.
func enclaveContainerInNetns(leaderPid int, work func() error) error {
	errs := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		own, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			runtime.UnlockOSThread()
			errs <- err
			return
		}
		defer unix.Close(own)
		target, err := unix.Open("/proc/"+strconv.Itoa(leaderPid)+"/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			runtime.UnlockOSThread()
			errs <- err
			return
		}
		defer unix.Close(target)
		if err := unix.Setns(target, unix.CLONE_NEWNET); err != nil {
			runtime.UnlockOSThread()
			errs <- err
			return
		}
		workErr := work()
		if err := unix.Setns(own, unix.CLONE_NEWNET); err != nil {
			// still locked: the thread ends with this goroutine
			errs <- errors.Join(workErr, err)
			return
		}
		runtime.UnlockOSThread()
		errs <- workErr
	}()
	return <-errs
}

// Opens /proc/<first process>/root, O_PATH.
func (self *enclaveContainerLinuxSystem) OpenRoot(leaderPid int) (*os.File, error) {
	fd, err := unix.Open("/proc/"+strconv.Itoa(leaderPid)+"/root", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "enclave-container-root"), nil
}

// Duplicates file's descriptor close-on-exec, under the file's own reference so a close meanwhile fails it.
func (self *enclaveContainerLinuxSystem) Dup(file *os.File) (*os.File, error) {
	raw, err := file.SyscallConn()
	if err != nil {
		return nil, err
	}
	fd := -1
	dupErr := error(nil)
	if err := raw.Control(func(original uintptr) {
		fd, dupErr = unix.FcntlInt(original, unix.F_DUPFD_CLOEXEC, 0)
	}); err != nil {
		return nil, err
	}
	if dupErr != nil {
		return nil, dupErr
	}
	return os.NewFile(uintptr(fd), file.Name()), nil
}

// Listens from a thread moved into the first process's network namespace and back.
func (self *enclaveContainerLinuxSystem) Listen(leaderPid int, network string, address string) (net.Listener, error) {
	var listener net.Listener
	err := enclaveContainerInNetns(leaderPid, func() error {
		var err error
		listener, err = net.Listen(network, address)
		return err
	})
	if err != nil {
		return nil, err
	}
	return listener, nil
}

// A namespace's identity, by the device and inode of its /proc file.
func enclaveContainerNamespaceOf(pid int, kind string) (uint64, uint64, error) {
	var stat unix.Stat_t
	if err := unix.Stat("/proc/"+strconv.Itoa(pid)+"/ns/"+kind, &stat); err != nil {
		return 0, 0, err
	}
	return stat.Dev, stat.Ino, nil
}

// Compares pid's PID namespace with the first process's and reads its pid there from NSpid.
func (self *enclaveContainerLinuxSystem) NamespacePid(pid int, leaderPid int) (int, bool) {
	dev, ino, err := enclaveContainerNamespaceOf(pid, "pid")
	if err != nil {
		return 0, false
	}
	leaderDev, leaderIno, err := enclaveContainerNamespaceOf(leaderPid, "pid")
	if err != nil || dev != leaderDev || ino != leaderIno {
		return 0, false
	}
	nspids, err := enclaveContainerNspids(pid)
	if err != nil || len(nspids) == 0 {
		return 0, false
	}
	return nspids[len(nspids)-1], true
}

// The container socket's peer by SO_PEERCRED: its pid, uid and gid as the daemon's namespaces see them.
func enclaveContainerPeerOfConn(conn net.Conn) (EnclaveContainerPeer, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return EnclaveContainerPeer{}, errors.New("not a unix socket")
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return EnclaveContainerPeer{}, err
	}
	var ucred *unix.Ucred
	credErr := errors.New("unread")
	if err := raw.Control(func(fd uintptr) {
		ucred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return EnclaveContainerPeer{}, err
	}
	if credErr != nil {
		return EnclaveContainerPeer{}, credErr
	}
	return EnclaveContainerPeer{Pid: int(ucred.Pid), Uid: ucred.Uid, Gid: ucred.Gid}, nil
}

// rtnetlink's format values (linux/rtnetlink.h, linux/if_addr.h): the main table, a static route's protocol and the
// universe scope.
const (
	enclaveNetlinkTableMain     = 254
	enclaveNetlinkProtoStatic   = 4
	enclaveNetlinkScopeUniverse = 0
	enclaveNetlinkTypeUnicast   = 1
)

// One rtnetlink request on a socket of the calling thread's network namespace, answered by its ack.
func enclaveNetlinkRequest(messageType uint16, flags uint16, body []byte) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	const sequence = 1
	message := make([]byte, unix.SizeofNlMsghdr, unix.SizeofNlMsghdr+len(body))
	binary.NativeEndian.PutUint32(message[0:4], uint32(unix.SizeofNlMsghdr+len(body)))
	binary.NativeEndian.PutUint16(message[4:6], messageType)
	binary.NativeEndian.PutUint16(message[6:8], flags|unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	binary.NativeEndian.PutUint32(message[8:12], sequence)
	message = append(message, body...)
	if err := unix.Sendto(fd, message, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	buffer := make([]byte, unix.Getpagesize())
	for {
		n, _, err := unix.Recvfrom(fd, buffer, 0)
		if err != nil {
			return err
		}
		messages, err := syscall.ParseNetlinkMessage(buffer[:n])
		if err != nil {
			return err
		}
		for _, reply := range messages {
			if reply.Header.Seq != sequence || reply.Header.Type != unix.NLMSG_ERROR {
				continue
			}
			if len(reply.Data) < 4 {
				return errors.New("a short netlink ack")
			}
			if errno := int32(binary.NativeEndian.Uint32(reply.Data[0:4])); errno != 0 {
				return unix.Errno(-errno)
			}
			return nil
		}
	}
}

// One rtattr: its length, type and value, padded to four bytes.
func enclaveNetlinkAttribute(attributeType uint16, value []byte) []byte {
	length := unix.SizeofRtAttr + len(value)
	attribute := make([]byte, (length+unix.RTA_ALIGNTO-1)&^(unix.RTA_ALIGNTO-1))
	binary.NativeEndian.PutUint16(attribute[0:2], uint16(length))
	binary.NativeEndian.PutUint16(attribute[2:4], attributeType)
	copy(attribute[unix.SizeofRtAttr:], value)
	return attribute
}

// Sets an interface up (RTM_NEWLINK with IFF_UP in its change mask).
func enclaveNetlinkSetUp(index int) error {
	body := make([]byte, unix.SizeofIfInfomsg)
	body[0] = unix.AF_UNSPEC
	binary.NativeEndian.PutUint32(body[4:8], uint32(index))
	binary.NativeEndian.PutUint32(body[8:12], unix.IFF_UP)
	binary.NativeEndian.PutUint32(body[12:16], unix.IFF_UP)
	return enclaveNetlinkRequest(unix.RTM_NEWLINK, 0, body)
}

// Puts an IPv4 address and prefix on an interface, replacing one there already.
func enclaveNetlinkAddAddress(index int, prefix netip.Prefix) error {
	address := prefix.Addr().As4()
	body := make([]byte, unix.SizeofIfAddrmsg)
	body[0] = unix.AF_INET
	body[1] = byte(prefix.Bits())
	body[3] = enclaveNetlinkScopeUniverse
	binary.NativeEndian.PutUint32(body[4:8], uint32(index))
	body = append(body, enclaveNetlinkAttribute(unix.IFA_LOCAL, address[:])...)
	body = append(body, enclaveNetlinkAttribute(unix.IFA_ADDRESS, address[:])...)
	return enclaveNetlinkRequest(unix.RTM_NEWADDR, unix.NLM_F_CREATE|unix.NLM_F_REPLACE, body)
}

// Routes the main table's IPv4 default through gateway on an interface, replacing one there already.
func enclaveNetlinkAddDefaultRoute(index int, gateway netip.Addr) error {
	address := gateway.As4()
	body := make([]byte, unix.SizeofRtMsg)
	body[0] = unix.AF_INET
	body[4] = enclaveNetlinkTableMain
	body[5] = enclaveNetlinkProtoStatic
	body[6] = enclaveNetlinkScopeUniverse
	body[7] = enclaveNetlinkTypeUnicast
	body = append(body, enclaveNetlinkAttribute(unix.RTA_GATEWAY, address[:])...)
	oif := make([]byte, 4)
	binary.NativeEndian.PutUint32(oif, uint32(index))
	body = append(body, enclaveNetlinkAttribute(unix.RTA_OIF, oif)...)
	return enclaveNetlinkRequest(unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_REPLACE, body)
}
