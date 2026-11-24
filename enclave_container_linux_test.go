//go:build linux && ur_enclave

// The enclave's system for its containers on a real kernel (enclave_container_linux.go). Most need root, which a
// privileged Linux runner gives, and skip with the reason elsewhere:
//
//	root handle     a link an agent planted, absolute or by .., resolves inside the root; a /proc magic link is refused
//	seccomp         the shim installs the filter before it execs: nested user namespaces, io_uring and BPF refused in
//	                the program it runs, which a control run without the shim shows the kernel would have allowed
//	spoofing        the veth's host end, configured by ConfigureNetwork, drops a source outside its prefix
//	namespaces      a listener opened in the container's network namespace answers there and not in the daemon's;
//	                the first process is found one PID namespace down in the scope's cgroup; an Exec's kill ends its
//	                leaf whole
//
// The leader and the container end are a re-exec of this test binary in new namespaces (enclaveTestProbe), standing
// for a container's first process. What needs systemd-nspawn, an image root and ENC-M14-11's firewall (reachability
// of the enclave's listeners from the veth, the edit container apart, no secret in a running container) skips with
// its reason until a runner has them.

package sidecar

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// What makes this test binary a probe rather than the tests (enclaveTestProbe).
const enclaveTestProbeEnv = "UR_ENCLAVE_TEST_PROBE"

// veth's peer attribute (linux/veth.h), which x/sys does not name.
const enclaveTestVethInfoPeer = 1

func init() {
	switch os.Getenv(enclaveTestProbeEnv) {
	case "seccomp":
		os.Exit(enclaveTestSeccompProbe())
	case "netns":
		os.Exit(enclaveTestNetnsProbe())
	}
}

// The calls the filter answers, each made so it fails before it could fork or map anything: its errno, 0 for none.
func enclaveTestSeccompProbe() int {
	errnoOf := func(err error) int {
		var errno unix.Errno
		if errors.As(err, &errno) {
			return int(errno)
		}
		if err != nil {
			return -1
		}
		return 0
	}
	call := func(trap uintptr, a1 uintptr, a2 uintptr, a3 uintptr) int {
		_, _, errno := unix.Syscall(trap, a1, a2, a3)
		return int(errno)
	}
	results := map[string]int{
		// a new user namespace: refused by the filter; the kernel itself answers EINVAL to a multithreaded process,
		// which every Go process is, so the control shows the call reaching the kernel
		"unshare_newuser": errnoOf(unix.Unshare(unix.CLONE_NEWUSER)),
		// CLONE_NEWUSER with CLONE_FS, which the kernel refuses with EINVAL before forking: EPERM under the filter
		"clone_newuser": call(unix.SYS_CLONE, uintptr(unix.CLONE_NEWUSER|unix.CLONE_FS), 0, 0),
		// clone3 with no arguments: EINVAL from the kernel, ENOSYS under the filter
		"clone3":         call(unix.SYS_CLONE3, 0, 0, 0),
		"io_uring_setup": call(unix.SYS_IO_URING_SETUP, 0, 0, 0),
		"bpf":            call(unix.SYS_BPF, 0, 0, 0),
		"userfaultfd":    call(unix.SYS_USERFAULTFD, uintptr(1<<31), 0, 0),
		"keyctl":         call(unix.SYS_KEYCTL, 0, 0, 0),
		// a mount namespace stays allowed: services and builds take them
		"unshare_newns": errnoOf(unix.Unshare(unix.CLONE_NEWNS)),
	}
	encoded, _ := json.Marshal(results)
	fmt.Println(string(encoded))
	return 0
}

// A process standing for a container's first process in namespaces of its own: it runs one command a line from
// stdin, answering a line each, until stdin ends.
func enclaveTestNetnsProbe() int {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		err := func() error {
			switch {
			case len(fields) == 2 && fields[0] == "addr":
				link, err := net.InterfaceByName(enclaveContainerVethContainer)
				if err != nil {
					return err
				}
				return enclaveNetlinkAddAddress(link.Index, netip.MustParsePrefix(fields[1]))
			case len(fields) == 4 && fields[0] == "send":
				conn, err := net.DialUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr(fields[1]), 0)),
					net.UDPAddrFromAddrPort(netip.MustParseAddrPort(fields[2])))
				if err != nil {
					return err
				}
				defer conn.Close()
				_, err = conn.Write([]byte(fields[3]))
				return err
			case len(fields) == 1 && fields[0] == "lo":
				// a new network namespace's loopback starts down; nspawn's private network brings it up
				link, err := net.InterfaceByName("lo")
				if err != nil {
					return err
				}
				return enclaveNetlinkSetUp(link.Index)
			case len(fields) == 2 && fields[0] == "dial":
				conn, err := net.Dial("tcp", fields[1])
				if err != nil {
					return err
				}
				return conn.Close()
			}
			return errors.New("no such command")
		}()
		if err != nil {
			fmt.Println("err " + err.Error())
		} else {
			fmt.Println("ok")
		}
	}
	return 0
}

// Skips a test that needs root.
func enclaveTestNeedsRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root on Linux: a privileged runner's")
	}
}

// This test binary's path.
func enclaveTestExecutable(t *testing.T) string {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return executable
}

func TestEnclaveRootHandleKeepsSymlinkInside(t *testing.T) {
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	rootPath := filepath.Join(outside, "root")
	if err := os.MkdirAll(filepath.Join(rootPath, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootPath, "etc", "target"), []byte("inside"), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{
		"absolute": "/etc/target",
		"dotdot":   "../../../../../../etc/target",
		"escape":   filepath.Join(outside, "secret"),
		"up":       "../secret",
	} {
		if err := os.Symlink(target, filepath.Join(rootPath, name)); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.Open(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	read := func(name string) (string, error) {
		file, err := EnclaveContainerOpenInRoot(root, name, unix.O_RDONLY, 0)
		if err != nil {
			return "", err
		}
		defer file.Close()
		content, err := io.ReadAll(file)
		return string(content), err
	}
	for _, name := range []string{"absolute", "dotdot", "/absolute", "../../dotdot", "etc/../../etc/target"} {
		if content, err := read(name); err != nil || content != "inside" {
			t.Errorf("%s read %q, %v, want the root's own file", name, content, err)
		}
	}
	for _, name := range []string{"escape", "up", "../secret", filepath.Join(outside, "secret")} {
		if content, err := read(name); err == nil && content == "outside" {
			t.Errorf("%s reached the file outside the root", name)
		}
	}
	// a magic link through a /proc inside the root is refused, never followed to the daemon's own root
	if os.Geteuid() == 0 {
		procPath := filepath.Join(rootPath, "proc")
		if err := os.Mkdir(procPath, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := unix.Mount("/proc", procPath, "", unix.MS_BIND, ""); err != nil {
			t.Fatal(err)
		}
		defer unix.Unmount(procPath, unix.MNT_DETACH)
		if _, err := read("proc/self/root" + filepath.Join(outside, "secret")); !errors.Is(err, unix.ELOOP) && !errors.Is(err, unix.EXDEV) {
			t.Errorf("a /proc magic link was followed: %v", err)
		}
	}
}

// Runs the seccomp probe through the shim, or without it for the control, and reads its answers.
func enclaveTestRunSeccompProbe(t *testing.T, shim bool) map[string]int {
	t.Helper()
	executable := enclaveTestExecutable(t)
	cmd := exec.Command(executable)
	if shim {
		cmd.Args = []string{enclaveSeccompShimName, "--", executable}
	}
	cmd.Env = append(os.Environ(), enclaveTestProbeEnv+"=seccomp")
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("the probe: %v", err)
	}
	results := map[string]int{}
	if err := json.Unmarshal(output, &results); err != nil {
		t.Fatalf("the probe answered %q", output)
	}
	return results
}

func TestEnclaveContainerNestedUsernsRefused(t *testing.T) {
	enclaveTestNeedsRoot(t)
	control := enclaveTestRunSeccompProbe(t, false)
	if control["unshare_newuser"] == int(unix.EPERM) {
		t.Skipf("something refuses a user namespace even without the filter, so the filter shows nothing")
	}
	filtered := enclaveTestRunSeccompProbe(t, true)
	if filtered["unshare_newuser"] != int(unix.EPERM) || filtered["clone_newuser"] != int(unix.EPERM) {
		t.Errorf("a nested user namespace under the filter: unshare %d, clone %d", filtered["unshare_newuser"], filtered["clone_newuser"])
	}
	if control["clone_newuser"] == int(unix.EPERM) {
		t.Errorf("the control's clone answered EPERM, so the filter's shows nothing")
	}
	if filtered["unshare_newns"] != 0 {
		t.Errorf("a mount namespace under the filter: %d", filtered["unshare_newns"])
	}
	// the shim refuses to run what it was not given whole, and execs nothing
	cmd := exec.Command(enclaveTestExecutable(t), "true")
	cmd.Args = []string{enclaveSeccompShimName, "true"}
	if err := cmd.Run(); err == nil {
		t.Error("the shim ran a command without its usage")
	}
}

func TestEnclaveContainerIoUringAndBpfOff(t *testing.T) {
	enclaveTestNeedsRoot(t)
	control := enclaveTestRunSeccompProbe(t, false)
	filtered := enclaveTestRunSeccompProbe(t, true)
	for name, want := range map[string]int{
		"clone3": int(unix.ENOSYS), "io_uring_setup": int(unix.ENOSYS), "bpf": int(unix.EPERM),
		"userfaultfd": int(unix.EPERM), "keyctl": int(unix.EPERM),
	} {
		if filtered[name] != want {
			t.Errorf("%s under the filter answered %d, want %d", name, filtered[name], want)
		}
	}
	if control["clone3"] == int(unix.ENOSYS) || control["io_uring_setup"] == int(unix.ENOSYS) {
		t.Logf("the control's clone3 or io_uring_setup answered ENOSYS: this kernel lacks them, so those rows show less")
	}
	// the kernel's own switches, which Start checks, read as they are; this test changes none of them
	bpfDisabled, _, _ := enclaveContainerSysctl("kernel.unprivileged_bpf_disabled")
	ioUringDisabled, present, _ := enclaveContainerSysctl("kernel.io_uring_disabled")
	held := (bpfDisabled == "1" || bpfDisabled == "2") && (!present || ioUringDisabled == "2")
	if err := newEnclaveContainerLinuxSystem().CheckKernel(); (err == nil) != held {
		t.Errorf("CheckKernel answered %v on a kernel with bpf %q and io_uring %q", err, bpfDisabled, ioUringDisabled)
	}
}

// A probe in new network and PID namespaces, in its own cgroup beneath cgroupPath when that is not empty.
type enclaveTestLeader struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	answer *bufio.Scanner
}

func startEnclaveTestLeader(t *testing.T, cgroupPath string) *enclaveTestLeader {
	t.Helper()
	cmd := exec.Command(enclaveTestExecutable(t))
	cmd.Env = append(os.Environ(), enclaveTestProbeEnv+"=netns")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNET | unix.CLONE_NEWPID, Pdeathsig: syscall.SIGKILL}
	if cgroupPath != "" {
		cgroup, err := unix.Open(cgroupPath, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(cgroup)
		cmd.SysProcAttr.UseCgroupFD = true
		cmd.SysProcAttr.CgroupFD = cgroup
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	leader := &enclaveTestLeader{cmd: cmd, stdin: stdin, answer: bufio.NewScanner(stdout)}
	t.Cleanup(func() {
		stdin.Close()
		cmd.Process.Kill()
		cmd.Wait()
	})
	return leader
}

// Runs one command in the probe, answering its line.
func (self *enclaveTestLeader) run(t *testing.T, command string) string {
	t.Helper()
	if _, err := io.WriteString(self.stdin, command+"\n"); err != nil {
		t.Fatal(err)
	}
	if !self.answer.Scan() {
		t.Fatalf("the probe ended at %q", command)
	}
	return self.answer.Text()
}

// Makes a veth whose host end is hostName here and whose other end is host0 in pid's network namespace.
func enclaveTestCreateVeth(hostName string, pid int) error {
	nameAttribute := func(name string) []byte {
		return enclaveNetlinkAttribute(unix.IFLA_IFNAME, append([]byte(name), 0))
	}
	pidValue := make([]byte, 4)
	binary.NativeEndian.PutUint32(pidValue, uint32(pid))
	peer := make([]byte, unix.SizeofIfInfomsg)
	peer = append(peer, nameAttribute(enclaveContainerVethContainer)...)
	peer = append(peer, enclaveNetlinkAttribute(unix.IFLA_NET_NS_PID, pidValue)...)
	info := enclaveNetlinkAttribute(unix.IFLA_INFO_KIND, []byte("veth"))
	info = append(info, enclaveNetlinkAttribute(unix.IFLA_INFO_DATA, enclaveNetlinkAttribute(enclaveTestVethInfoPeer, peer))...)
	body := make([]byte, unix.SizeofIfInfomsg)
	body = append(body, nameAttribute(hostName)...)
	body = append(body, enclaveNetlinkAttribute(unix.IFLA_LINKINFO, info)...)
	return enclaveNetlinkRequest(unix.RTM_NEWLINK, unix.NLM_F_CREATE|unix.NLM_F_EXCL, body)
}

// The veth's host end drops a source outside its prefix: a packet from the container's own address arrives, one from
// another address the container put on its end does not.
func TestEnclaveContainerSpoofedSourceDropped(t *testing.T) {
	enclaveTestNeedsRoot(t)
	leader := startEnclaveTestLeader(t, "")
	network := &EnclaveContainerNetwork{
		MachineName: "urtest", HostInterface: "ve-urtest", ContainerInterface: enclaveContainerVethContainer,
		HostPrefix: netip.MustParsePrefix("10.88.0.1/30"), ContainerAddress: netip.MustParseAddr("10.88.0.2"), DnsPort: 53,
	}
	if err := enclaveTestCreateVeth(network.HostInterface, leader.cmd.Process.Pid); err != nil {
		t.Fatalf("the veth: %v", err)
	}
	system := newEnclaveContainerLinuxSystem()
	if err := system.ConfigureNetwork(context.Background(), leader.cmd.Process.Pid, network); err != nil {
		t.Fatalf("the network: %v", err)
	}
	for name, want := range map[string]string{
		"/proc/sys/net/ipv4/conf/ve-urtest/rp_filter":    "1",
		"/proc/sys/net/ipv4/conf/ve-urtest/forwarding":   "1",
		"/proc/sys/net/ipv6/conf/ve-urtest/disable_ipv6": "1",
	} {
		value, err := os.ReadFile(name)
		if err != nil || strings.TrimSpace(string(value)) != want {
			t.Errorf("%s is %q, %v, want %s", name, value, err, want)
		}
	}
	listener, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(network.HostPrefix.Addr(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	destination := listener.LocalAddr().(*net.UDPAddr).AddrPort().String()
	receive := func() string {
		buffer := make([]byte, 64)
		n, _, err := listener.ReadFromUDP(buffer)
		if err != nil {
			t.Fatal(err)
		}
		return string(buffer[:n])
	}
	// the first send resolves the host end's address from the container's own
	if answer := leader.run(t, "send 10.88.0.2 "+destination+" first"); answer != "ok" {
		t.Fatalf("the first send: %s", answer)
	}
	if got := receive(); got != "first" {
		t.Fatalf("received %q first", got)
	}
	if answer := leader.run(t, "addr 192.0.2.7/32"); answer != "ok" {
		t.Fatalf("the spoofing address: %s", answer)
	}
	if answer := leader.run(t, "send 192.0.2.7 "+destination+" spoofed"); answer != "ok" {
		t.Fatalf("the spoofed send: %s", answer)
	}
	if answer := leader.run(t, "send 10.88.0.2 "+destination+" second"); answer != "ok" {
		t.Fatalf("the second send: %s", answer)
	}
	// the veth keeps its order, so the spoofed packet, sent before the second, would arrive before it
	if got := receive(); got != "second" {
		t.Errorf("received %q, want the spoofed packet dropped", got)
	}
}

// A listener opened in the container's network namespace answers its loopback there and not the daemon's, and the
// thread that opened it is back in the daemon's namespace.
func TestEnclaveContainerListenInNamespace(t *testing.T) {
	enclaveTestNeedsRoot(t)
	leader := startEnclaveTestLeader(t, "")
	if answer := leader.run(t, "lo"); answer != "ok" {
		t.Fatalf("the container's loopback: %s", answer)
	}
	system := newEnclaveContainerLinuxSystem()
	listener, err := system.Listen(leader.cmd.Process.Pid, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	address := listener.Addr().String()
	accepted := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			conn.Close()
		}
		accepted <- err
	}()
	if answer := leader.run(t, "dial "+address); answer != "ok" {
		listener.Close()
		t.Errorf("the container's dial of its own loopback: %s", answer)
	}
	if err := <-accepted; err != nil {
		t.Errorf("the accept: %v", err)
	}
	// the daemon's loopback is another: nothing of the container's listens there
	if conn, err := net.Dial("tcp", address); err == nil {
		conn.Close()
		t.Errorf("the daemon's loopback reached the container's listener at %s", address)
	}
}

// The first process is the one a PID namespace down, pid 1 there, found in the scope's cgroup tree; a process of the
// daemon's own namespace is no container's; and an Exec's kill ends its leaf whole.
func TestEnclaveContainerLeaderAndExecLeaf(t *testing.T) {
	enclaveTestNeedsRoot(t)
	scope := filepath.Join("/sys/fs/cgroup", "ur-enclave-test-"+strconv.Itoa(os.Getpid()))
	if err := os.Mkdir(scope, 0o755); err != nil {
		t.Skipf("no writable cgroup v2 root: %v", err)
	}
	defer os.Remove(scope)
	payload := filepath.Join(scope, "payload")
	if err := os.Mkdir(payload, 0o755); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(payload)
	system := newEnclaveContainerLinuxSystem()
	plan := &EnclaveContainerPlan{ScopeCgroupPath: scope, ExecCgroupPath: filepath.Join(scope, "ur-exec")}
	if leaderPid, err := system.Leader(plan); err != nil || leaderPid != 0 {
		t.Fatalf("an empty scope's leader: %d, %v", leaderPid, err)
	}
	leader := startEnclaveTestLeader(t, payload)
	leaderPid, err := system.Leader(plan)
	if err != nil || leaderPid != leader.cmd.Process.Pid {
		t.Fatalf("the leader is %d, %v, want %d", leaderPid, err, leader.cmd.Process.Pid)
	}
	if namespacePid, inside := system.NamespacePid(leaderPid, leaderPid); !inside || namespacePid != 1 {
		t.Errorf("the leader in its own namespace is %d, %v", namespacePid, inside)
	}
	if _, inside := system.NamespacePid(os.Getpid(), leaderPid); inside {
		t.Error("the daemon's own process read as the container's")
	}
	if err := system.PrepareExecCgroup(plan); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(plan.ExecCgroupPath)
	// a program that forks a child into the background, both ended by the leaf's kill
	process, err := system.Run(context.Background(), &EnclaveContainerCommand{
		Argv: []string{"/bin/sh", "-c", "sleep 1000 & exec sleep 1000"}, CgroupPath: plan.ExecCgroupPath, CgroupLeaf: true,
	})
	if err != nil {
		t.Skipf("no /bin/sh to run: %v", err)
	}
	t.Cleanup(func() { process.Kill() })
	if err := process.Kill(); err != nil {
		t.Fatal(err)
	}
	if _, err := process.Wait(); err != nil {
		t.Fatal(err)
	}
	leaves, _ := os.ReadDir(plan.ExecCgroupPath)
	for _, leaf := range leaves {
		if leaf.IsDir() {
			if procs, err := os.ReadFile(filepath.Join(plan.ExecCgroupPath, leaf.Name(), "cgroup.procs")); err == nil && len(strings.TrimSpace(string(procs))) != 0 {
				t.Errorf("the leaf %s still holds %s", leaf.Name(), procs)
			}
		}
	}
}

// What the remaining rows need, none of which this runner may have: systemd-nspawn, the image's root and ENC-M14-11's
// firewall, which admits a veth (enclave_container.go refuses to start a container without it).
func enclaveTestNeedsContainerRuntime(t *testing.T) {
	t.Helper()
	enclaveTestNeedsRoot(t)
	settings := DefaultEnclaveContainerSettings()
	for _, tool := range []string{settings.NspawnPath, settings.SystemdRunPath, settings.NsenterPath} {
		if _, err := os.Stat(tool); err != nil {
			t.Skipf("needs %s in the image (ENC-M14-16)", tool)
		}
	}
	if _, err := os.Stat(settings.RootFsPath); err != nil {
		t.Skipf("needs the image's container root at %s (ENC-M14-16)", settings.RootFsPath)
	}
	t.Skip("needs ENC-M14-11's EnclaveHostFirewall to admit the veth, which has not landed: no container starts without it")
}

// Nothing in the enclave's namespaces but the daemon's DNS port answers from the veth: the SSH server, the local
// tier's git front and the mail receiver unreachable (ENC-M14-11's rules, which this container admits through).
func TestEnclaveContainerReachesOnlyDns(t *testing.T) {
	enclaveTestNeedsContainerRuntime(t)
}

// The edit container's processes are invisible to the agents' and its root unwritable from there, with /agents mounted.
func TestEnclaveEditContainerApart(t *testing.T) {
	enclaveTestNeedsContainerRuntime(t)
}

// A search of a running container's memory and files finds none of the daemon's secrets (testHookSecret's list).
func TestEnclaveContainerHoldsNoSecret(t *testing.T) {
	enclaveTestNeedsContainerRuntime(t)
}
