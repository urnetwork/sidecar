//go:build !ios_extension && !sidecar_http

// Confining the ur-engine helper (DESIGN-COMPUTE §6.5, R-INFER-2, D-INFER-2; INFER-M11-05): the OS holds the helper to
// reading its engine's files and its model files, the system's libraries and the GPU's device nodes, with no network,
// so a crash, a leak or a hostile model file takes the engine and reaches nothing the daemon holds.
//
//	linux    the helper, before it loads anything, applies Landlock, read-only on those paths and nothing writable,
//	         and a seccomp filter that refuses sockets, on the one thread that then execs the helper again, so every
//	         thread of the image that loads the engine runs confined; it refuses to run where the kernel offers no
//	         Landlock, and the daemon then lists local inference unavailable with that reason
//	         (infer_engine_confine_linux.go)
//	windows  the daemon starts the helper in an AppContainer with no capabilities, granting it read on the two
//	         directories and on its own executable by ACL; the helper refuses to run outside an AppContainer
//	         (infer_engine_confine_windows.go)
//	macos    the helper is its own signed executable inside ur.app, ur-engine.app with its own identifier, the
//	         hardened runtime and the App Sandbox, whose entitlements give it read-only exceptions for the two
//	         directories and library validation off, which ur's own never take (build/all/ur/macos/); at run time
//	         there is only the proof below (infer_engine_confine_darwin.go)
//	other    nothing confines a helper, so none runs (infer_engine_confine_other.go)
//
// Whatever the OS, the helper then proves it before it serves: it lists the directory the daemon names denied, the
// instance's state directory, and refuses to run if it can, so a helper that is not confined, a build signed without
// its entitlements among them, serves nothing. A confinement step that fails stops the helper, and confinement is
// applied before the first library load, never after. The daemon names what to confine to in the helper's environment
// (inferEngineConfineEnvironment), beside the entries its args name: paths alone, no secret. The environment, not the
// arguments, so an executable that parses its own flags, a test binary among them, runs as a helper unchanged.
//
// Every function here is safe for concurrent use: each is a function of its arguments.

package sidecar

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/net/bpf"
)

// What the helper is confined to (§6.5): its engine's files and its model files, read-only, beside the system's
// libraries and the GPU's device nodes, which each OS's code names.
type inferEngineConfinement struct {
	// Where the engine's libraries, its GPU plugins and Dawn are pulled to: <state>/engine on a desktop.
	EngineDirectory string
	// Where the model files are pulled to: <state>/models on a desktop.
	ModelDirectory string
	// A directory the helper must not read once confined: the instance's state directory, which holds its keys'
	// wraps. The helper lists it once confined, and runs nothing if it can.
	DeniedDirectory string
}

// The helper's environment entries that name what to confine it to, each once.
const (
	inferEngineEnvEngineDirectory = "UR_ENGINE_DIRECTORY"
	inferEngineEnvModelDirectory  = "UR_ENGINE_MODEL_DIRECTORY"
	inferEngineEnvDeniedDirectory = "UR_ENGINE_DENIED_DIRECTORY"
)

// A helper whose environment does not name what to confine it to, or a confinement whose paths are not absolute and
// apart.
var errInferEngineConfinementInvalid = errors.New("engine helper: what to confine it to is not three absolute directories apart")

// The engine helper is not confined, so it runs nothing (§6.5).
var ErrInferEngineUnconfined = errors.New("the engine helper is not confined")

// Nil where the confinement's directories are absolute and clean, the denied one outside the two the helper reads and
// neither of those inside it.
func (self *inferEngineConfinement) validate() error {
	if self == nil {
		return errInferEngineConfinementInvalid
	}
	paths := []string{self.EngineDirectory, self.ModelDirectory, self.DeniedDirectory}
	for _, path := range paths {
		if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return errInferEngineConfinementInvalid
		}
	}
	within := func(path string, directory string) bool {
		relative, err := filepath.Rel(directory, path)
		return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
	}
	for _, allowed := range paths[:2] {
		// the denied directory may hold the two, as <state> holds engine/ and models/, but never sit inside one
		if within(self.DeniedDirectory, allowed) {
			return errInferEngineConfinementInvalid
		}
	}
	return nil
}

// The helper's environment entries for confinement, which parseInferEngineConfineEnvironment reads back.
func inferEngineConfineEnvironment(confinement *inferEngineConfinement) []string {
	return []string{
		inferEngineEnvEngineDirectory + "=" + confinement.EngineDirectory,
		inferEngineEnvModelDirectory + "=" + confinement.ModelDirectory,
		inferEngineEnvDeniedDirectory + "=" + confinement.DeniedDirectory,
	}
}

// The confinement env names, refused unless it names each of the three once, each valid: a helper that is not told
// what to confine itself to runs nothing.
func parseInferEngineConfineEnvironment(env []string) (*inferEngineConfinement, error) {
	values := map[string][]string{}
	for _, entry := range env {
		name, value, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		switch name {
		case inferEngineEnvEngineDirectory, inferEngineEnvModelDirectory, inferEngineEnvDeniedDirectory:
			values[name] = append(values[name], value)
		}
	}
	for _, name := range []string{inferEngineEnvEngineDirectory, inferEngineEnvModelDirectory, inferEngineEnvDeniedDirectory} {
		if len(values[name]) != 1 {
			return nil, errInferEngineConfinementInvalid
		}
	}
	confinement := &inferEngineConfinement{
		EngineDirectory: values[inferEngineEnvEngineDirectory][0],
		ModelDirectory:  values[inferEngineEnvModelDirectory][0],
		DeniedDirectory: values[inferEngineEnvDeniedDirectory][0],
	}
	if err := confinement.validate(); err != nil {
		return nil, err
	}
	return confinement, nil
}

// Nil where this process cannot list denied, as a confined helper must not: only a refusal by permission proves it, so
// a directory that is not there proves nothing. Else why the helper is not confined, naming no path.
func inferEngineConfineProbe(denied string) error {
	_, err := os.ReadDir(denied)
	switch {
	case err == nil:
		return fmt.Errorf("%w: it can list the instance's state directory", ErrInferEngineUnconfined)
	case errors.Is(err, fs.ErrPermission):
		return nil
	}
	return fmt.Errorf("%w: the instance's state directory does not read, but not for want of permission", ErrInferEngineUnconfined)
}

// How the daemon starts one helper process.
type inferEngineChildSpec struct {
	// The helper's executable, and its arguments.
	Path string
	Args []string
	// Its environment: nothing else is passed but the confinement's entries.
	Env []string
	// Its working directory.
	Directory string
	// What its stderr writes to.
	Stderr io.Writer
	// What the helper is confined to.
	Confinement *inferEngineConfinement
}

// One started helper process: its stdin and stdout, and how to end it and wait for it. kill may be called at any time,
// more than once; wait once, after the stdout has been read to its end or kill called.
type inferEngineChild struct {
	stdin  io.WriteCloser
	stdout io.ReadCloser
	kill   func() error
	wait   func() error
}

// The helper's arguments for spec, its executable first.
func (self *inferEngineChildSpec) argv() []string {
	return slices.Concat([]string{self.Path}, self.Args)
}

// The helper's whole environment for spec: its own entries and the confinement's.
func (self *inferEngineChildSpec) environment() []string {
	return slices.Concat(self.Env, inferEngineConfineEnvironment(self.Confinement))
}

// The helper started by an exec, with only spec's arguments, environment and stdio: how Linux and macOS start it,
// where the helper's own first steps (Linux) or its signature (macOS) confine it.
func inferEngineStartExecChild(spec *inferEngineChildSpec) (*inferEngineChild, error) {
	if err := spec.Confinement.validate(); err != nil {
		return nil, err
	}
	command := exec.Command(spec.Path, spec.Args...)
	// a nil Env inherits the daemon's, which this never is
	command.Env = spec.environment()
	command.Dir = spec.Directory
	stdin, err := command.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, err
	}
	command.Stderr = spec.Stderr
	if err := command.Start(); err != nil {
		return nil, err
	}
	return &inferEngineChild{
		stdin:  stdin,
		stdout: stdout,
		kill:   command.Process.Kill,
		wait:   command.Wait,
	}, nil
}

// Seccomp's and the kernel's ABI values the helper's filter is made of (linux/seccomp.h, linux/audit.h,
// asm-generic/errno-base.h), the same on amd64 and arm64: identifiers, not settings.
const (
	inferEngineSeccompRetKillProcess = uint32(0x80000000)
	inferEngineSeccompRetErrno       = uint32(0x00050000)
	inferEngineSeccompRetAllow       = uint32(0x7fff0000)
	inferEngineSeccompErrnoEacces    = uint32(13)
	inferEngineSeccompErrnoEnosys    = uint32(38)
	// x32's calls on amd64 carry this bit in their number.
	inferEngineSeccompX32SyscallBit = uint32(0x40000000)
	// struct seccomp_data: nr at 0, arch at 4; seccomp's BPF reads 32-bit words alone.
	inferEngineSeccompDataNrOffset   = uint32(0)
	inferEngineSeccompDataArchOffset = uint32(4)
	inferEngineSeccompLoadSize       = 4
)

// One architecture's ABI for the helper's filter (arch/x86/entry/syscalls/syscall_64.tbl,
// include/uapi/asm-generic/unistd.h).
type inferEngineSeccompArchitecture struct {
	auditArch uint32
	// whether x32's calls share the native audit value and must be told apart by their number
	x32 bool
	// the calls refused, each with its errno
	refusals []*inferEngineSeccompRefusal
}

// One call the filter refuses, and the errno it answers.
type inferEngineSeccompRefusal struct {
	name   string
	number uint32
	errno  uint32
}

// The architectures the helper is built for on Linux (§6.5's desktop row: linux/amd64 and linux/arm64), each refusing
// socket and socketpair with EACCES, so no network and no local socket, the daemon's among them, is reachable, and
// io_uring's calls with ENOSYS, since io_uring makes sockets without the socket call.
var inferEngineSeccompArchitectures = map[string]*inferEngineSeccompArchitecture{
	"amd64": {
		auditArch: 0xc000003e,
		x32:       true,
		refusals: []*inferEngineSeccompRefusal{
			{name: "socket", number: 41, errno: inferEngineSeccompErrnoEacces},
			{name: "socketpair", number: 53, errno: inferEngineSeccompErrnoEacces},
			{name: "io_uring_setup", number: 425, errno: inferEngineSeccompErrnoEnosys},
			{name: "io_uring_enter", number: 426, errno: inferEngineSeccompErrnoEnosys},
			{name: "io_uring_register", number: 427, errno: inferEngineSeccompErrnoEnosys},
		},
	},
	"arm64": {
		auditArch: 0xc00000b7,
		refusals: []*inferEngineSeccompRefusal{
			{name: "socket", number: 198, errno: inferEngineSeccompErrnoEacces},
			{name: "socketpair", number: 199, errno: inferEngineSeccompErrnoEacces},
			{name: "io_uring_setup", number: 425, errno: inferEngineSeccompErrnoEnosys},
			{name: "io_uring_enter", number: 426, errno: inferEngineSeccompErrnoEnosys},
			{name: "io_uring_register", number: 427, errno: inferEngineSeccompErrnoEnosys},
		},
	},
}

// The helper's seccomp filter for goarch, amd64 or arm64, as classic BPF over struct seccomp_data: a call of another
// architecture's ABI, x32's on amd64 among them, ends the process, since the numbers are the native ABI's; each refused
// call answers its errno; anything else is allowed. Assemble it to install it; run it on bpf's VM to test it.
func inferEngineSeccompProgram(goarch string) ([]bpf.Instruction, error) {
	architecture, ok := inferEngineSeccompArchitectures[goarch]
	if !ok {
		return nil, fmt.Errorf("no engine seccomp filter is made for %s", goarch)
	}
	program := []bpf.Instruction{
		bpf.LoadAbsolute{Off: inferEngineSeccompDataArchOffset, Size: inferEngineSeccompLoadSize},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: architecture.auditArch, SkipTrue: 1},
		bpf.RetConstant{Val: inferEngineSeccompRetKillProcess},
		bpf.LoadAbsolute{Off: inferEngineSeccompDataNrOffset, Size: inferEngineSeccompLoadSize},
	}
	if architecture.x32 {
		program = append(program,
			bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: inferEngineSeccompX32SyscallBit, SkipFalse: 1},
			bpf.RetConstant{Val: inferEngineSeccompRetKillProcess},
		)
	}
	for _, refusal := range architecture.refusals {
		program = append(program,
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: refusal.number, SkipFalse: 1},
			bpf.RetConstant{Val: inferEngineSeccompRetErrno | refusal.errno},
		)
	}
	program = append(program, bpf.RetConstant{Val: inferEngineSeccompRetAllow})
	if _, err := bpf.Assemble(program); err != nil {
		return nil, err
	}
	return program, nil
}

// Landlock's access rights and scopes (linux/landlock.h): ABI identifiers, not settings, named here so the rights a
// ruleset takes are computed and tested on every leg.
const (
	inferLandlockFsExecute    = uint64(0x1)
	inferLandlockFsWriteFile  = uint64(0x2)
	inferLandlockFsReadFile   = uint64(0x4)
	inferLandlockFsReadDir    = uint64(0x8)
	inferLandlockFsRemoveDir  = uint64(0x10)
	inferLandlockFsRemoveFile = uint64(0x20)
	inferLandlockFsMakeChar   = uint64(0x40)
	inferLandlockFsMakeDir    = uint64(0x80)
	inferLandlockFsMakeReg    = uint64(0x100)
	inferLandlockFsMakeSock   = uint64(0x200)
	inferLandlockFsMakeFifo   = uint64(0x400)
	inferLandlockFsMakeBlock  = uint64(0x800)
	inferLandlockFsMakeSym    = uint64(0x1000)
	// ABI 2
	inferLandlockFsRefer = uint64(0x2000)
	// ABI 3
	inferLandlockFsTruncate = uint64(0x4000)
	// ABI 5
	inferLandlockFsIoctlDev = uint64(0x8000)
	// ABI 4
	inferLandlockNetBindTcp    = uint64(0x1)
	inferLandlockNetConnectTcp = uint64(0x2)
	// ABI 6
	inferLandlockScopeAbstractUnixSocket = uint64(0x1)
	inferLandlockScopeSignal             = uint64(0x2)
	// The rights a rule on a file may grant: the rest are a directory's alone.
	inferLandlockFsFileRights = inferLandlockFsExecute | inferLandlockFsWriteFile | inferLandlockFsReadFile |
		inferLandlockFsTruncate | inferLandlockFsIoctlDev
	// struct landlock_ruleset_attr's size as each ABI first read it: handled_access_fs; then handled_access_net; then
	// scoped.
	inferLandlockAttrSizeFs    = 8
	inferLandlockAttrSizeNet   = 16
	inferLandlockAttrSizeScope = 24
)

// What a Landlock ruleset of one ABI handles, denying it everywhere no rule grants it, and what each kind of path the
// helper reads is granted.
type inferLandlockRights struct {
	abi int
	// Every file system right the ABI knows: nothing is writable, creatable, removable or executable but by a rule.
	handledFs uint64
	// TCP binds and connects, from ABI 4, beside the seccomp filter's refusal of sockets.
	handledNet uint64
	// Abstract unix sockets and signals outside the helper's domain, from ABI 6.
	scoped uint64
	// A directory read beneath: its files and listings.
	readDirectory uint64
	// A file read: a system file such as the loader's cache.
	readFile uint64
	// The helper's own executable and its ELF interpreter, which its exec into the confined image runs.
	execFile uint64
	// A GPU's device node, or a directory of them: opened to read and write, with ioctl from ABI 5. A device node holds
	// no file, so nothing on disk becomes writable.
	device uint64
	// The bytes of struct landlock_ruleset_attr the ruleset is created with.
	attrSize int
}

// The rights for a kernel whose Landlock ABI is abi; refused where the kernel offers no Landlock (abi below 1), so local
// inference is unavailable rather than unconfined (§6.5).
func inferLandlockRightsFor(abi int) (*inferLandlockRights, error) {
	if abi < 1 {
		return nil, fmt.Errorf("%w: the kernel offers no Landlock", ErrInferEngineUnconfined)
	}
	rights := &inferLandlockRights{
		abi: abi,
		handledFs: inferLandlockFsExecute | inferLandlockFsWriteFile | inferLandlockFsReadFile | inferLandlockFsReadDir |
			inferLandlockFsRemoveDir | inferLandlockFsRemoveFile | inferLandlockFsMakeChar | inferLandlockFsMakeDir |
			inferLandlockFsMakeReg | inferLandlockFsMakeSock | inferLandlockFsMakeFifo | inferLandlockFsMakeBlock |
			inferLandlockFsMakeSym,
		readDirectory: inferLandlockFsReadFile | inferLandlockFsReadDir,
		readFile:      inferLandlockFsReadFile,
		execFile:      inferLandlockFsReadFile | inferLandlockFsExecute,
		device:        inferLandlockFsReadFile | inferLandlockFsWriteFile,
		attrSize:      inferLandlockAttrSizeFs,
	}
	if 2 <= abi {
		rights.handledFs |= inferLandlockFsRefer
	}
	if 3 <= abi {
		rights.handledFs |= inferLandlockFsTruncate
	}
	if 4 <= abi {
		rights.handledNet = inferLandlockNetBindTcp | inferLandlockNetConnectTcp
		rights.attrSize = inferLandlockAttrSizeNet
	}
	if 5 <= abi {
		rights.handledFs |= inferLandlockFsIoctlDev
		rights.device |= inferLandlockFsIoctlDev
	}
	if 6 <= abi {
		rights.scoped = inferLandlockScopeAbstractUnixSocket | inferLandlockScopeSignal
		rights.attrSize = inferLandlockAttrSizeScope
	}
	return rights, nil
}

// access as a rule on a file may grant it: a directory's rights dropped, since the kernel refuses them on a file.
func inferLandlockFileAccess(access uint64) uint64 {
	return access & inferLandlockFsFileRights
}
