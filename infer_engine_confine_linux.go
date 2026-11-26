//go:build linux && !android && !ios_extension && !sidecar_http

// The helper's confinement on Linux (DESIGN-COMPUTE §6.5; infer_engine_confine.go): Landlock and a seccomp filter.
//
// Both are a thread's: landlock_restrict_self and a seccomp filter without TSYNC act on the calling thread, and the
// runtime's other threads already run when main starts. The helper does not try to reach them, since purego's runtime
// (the helper's binding links it) answers ENOTSUP to syscall.AllThreadsSyscall. Instead the first stage, on one locked
// thread, sets no_new_privs, restricts that thread with the ruleset, installs the filter and execs the helper again from
// it: a domain, a filter and no_new_privs all hold across execve, so every thread of the image that loads the engine is
// a descendant of a confined one. The second stage, which UR_ENGINE_CONFINED marks, proves it is confined (no_new_privs
// set, a filter in place, a socket refused, the denied directory unlistable) and only then serves.
//
// The ruleset handles every file system right the kernel's ABI knows, so nothing is writable, creatable, removable or
// executable but by a rule, TCP binds and connects from ABI 4 and abstract unix sockets and signals from ABI 6. Its
// rules: the engine's and the model directories read-only; the system paths InferSettings.EngineConfineSystemReadPaths
// names, read-only, each that exists; the device nodes EngineConfineDevicePaths names, read and write with ioctl, each
// that exists; and the helper's own executable and its ELF interpreter, read and execute, for the exec into the
// confined image. A kernel with no Landlock refuses: the helper runs nothing, and the daemon's InferEngineProcess
// lists local inference unavailable with that reason (inferEngineConfineAvailable).

package sidecar

import (
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// What the helper's second stage finds in its environment: it runs confined, so it proves that rather than confining
// itself again. A marker set by anyone else proves nothing, since the proof checks what the kernel holds.
const inferEngineConfinedEnvironment = "UR_ENGINE_CONFINED=1"

// The kernel's Landlock ABI version, or an error where it offers none: a test's seam.
var inferEngineLandlockAbi = func() (int, error) {
	abi, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 {
		return 0, errno
	}
	return int(abi), nil
}

// See infer_engine_confine.go: nil where the kernel offers Landlock, so a helper can be confined here.
func inferEngineConfineAvailable() error {
	abi, err := inferEngineLandlockAbi()
	if err != nil {
		return fmt.Errorf("%w: the kernel offers no Landlock (%s), so local inference is unavailable here", ErrInferEngineUnconfined, err)
	}
	if _, err := inferLandlockRightsFor(abi); err != nil {
		return err
	}
	return nil
}

// See infer_engine_confine.go: the helper beside ur.
func inferEngineDefaultHelperPath(executable string) string {
	return filepath.Join(filepath.Dir(executable), inferEngineHelperName())
}

// See infer_engine_confine.go: an exec of the helper, which confines itself.
func inferEngineStartChild(spec *inferEngineChildSpec) (*inferEngineChild, error) {
	return inferEngineStartExecChild(spec)
}

// Confines this process, the helper, before it loads anything (see the file comment): the first stage confines its
// thread and execs argv again, with env and the marker, returning only where a step failed; the second stage, the
// marker set, returns nil once it has proved itself confined. An error stops the helper.
func inferEngineConfine(confinement *inferEngineConfinement, settings *InferSettings, argv []string, env []string) error {
	if err := confinement.validate(); err != nil {
		return err
	}
	if slices.Contains(env, inferEngineConfinedEnvironment) {
		return inferEngineConfinedProof(confinement)
	}
	abi, err := inferEngineLandlockAbi()
	if err != nil {
		return fmt.Errorf("%w: the kernel offers no Landlock (%s)", ErrInferEngineUnconfined, err)
	}
	rights, err := inferLandlockRightsFor(abi)
	if err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("%w: where the helper runs from: %s", ErrInferEngineUnconfined, err)
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return fmt.Errorf("%w: where the helper runs from: %s", ErrInferEngineUnconfined, err)
	}
	program, err := inferEngineSeccompProgram(runtime.GOARCH)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrInferEngineUnconfined, err)
	}
	raw, err := bpf.Assemble(program)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrInferEngineUnconfined, err)
	}
	// every step from here acts on this thread, which the exec carries into the confined image; it is never unlocked,
	// since a failure ends the helper
	runtime.LockOSThread()
	ruleset, err := inferEngineLandlockRuleset(confinement, settings, rights, executable)
	if err != nil {
		return err
	}
	defer unix.Close(ruleset)
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("%w: no_new_privs: %s", ErrInferEngineUnconfined, err)
	}
	if _, _, errno := unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(ruleset), 0, 0); errno != 0 {
		return fmt.Errorf("%w: landlock_restrict_self: %s", ErrInferEngineUnconfined, errno)
	}
	filters := make([]unix.SockFilter, len(raw))
	for i, instruction := range raw {
		filters[i] = unix.SockFilter{Code: instruction.Op, Jt: instruction.Jt, Jf: instruction.Jf, K: instruction.K}
	}
	fprog := unix.SockFprog{Len: uint16(len(filters)), Filter: &filters[0]}
	_, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, 0, uintptr(unsafe.Pointer(&fprog)))
	runtime.KeepAlive(filters)
	if errno != 0 {
		return fmt.Errorf("%w: the seccomp filter: %s", ErrInferEngineUnconfined, errno)
	}
	testHookBarrier("infer.engine.confine.exec.before", "")
	err = unix.Exec(executable, argv, append(slices.Clone(env), inferEngineConfinedEnvironment))
	return fmt.Errorf("%w: the exec into the confined image: %s", ErrInferEngineUnconfined, err)
}

// The ruleset over rights: the two directories, the system's paths, the device nodes, the executable and its
// interpreter. The two directories must exist; a system path or device node that does not is passed over.
func inferEngineLandlockRuleset(confinement *inferEngineConfinement, settings *InferSettings, rights *inferLandlockRights, executable string) (int, error) {
	attr := unix.LandlockRulesetAttr{
		Handled_access_fs:  rights.handledFs,
		Handled_access_net: rights.handledNet,
		Scoped:             rights.scoped,
	}
	fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), uintptr(rights.attrSize), 0)
	if errno != 0 {
		return -1, fmt.Errorf("%w: landlock_create_ruleset: %s", ErrInferEngineUnconfined, errno)
	}
	ruleset := int(fd)
	// grants access on path, beneath it for a directory; a file takes its file rights alone. optional passes over a
	// path that is not there.
	add := func(path string, access uint64, optional bool) error {
		pathFd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil {
			if optional && errors.Is(err, unix.ENOENT) {
				return nil
			}
			return fmt.Errorf("%w: a rule's path does not open: %s", ErrInferEngineUnconfined, err)
		}
		defer unix.Close(pathFd)
		var stat unix.Stat_t
		if err := unix.Fstat(pathFd, &stat); err != nil {
			return fmt.Errorf("%w: a rule's path does not stat: %s", ErrInferEngineUnconfined, err)
		}
		if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
			access = inferLandlockFileAccess(access)
		}
		if access == 0 {
			return nil
		}
		rule := unix.LandlockPathBeneathAttr{Allowed_access: access, Parent_fd: int32(pathFd)}
		_, _, errno := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, uintptr(ruleset), unix.LANDLOCK_RULE_PATH_BENEATH,
			uintptr(unsafe.Pointer(&rule)), 0, 0, 0)
		if errno != 0 {
			return fmt.Errorf("%w: landlock_add_rule: %s", ErrInferEngineUnconfined, errno)
		}
		return nil
	}
	type landlockRule struct {
		path     string
		access   uint64
		optional bool
	}
	rules := []*landlockRule{
		{path: confinement.EngineDirectory, access: rights.readDirectory},
		{path: confinement.ModelDirectory, access: rights.readDirectory},
		{path: executable, access: rights.execFile},
	}
	if interpreter := inferEngineElfInterpreter(executable); interpreter != "" {
		rules = append(rules, &landlockRule{path: interpreter, access: rights.execFile})
	}
	for _, path := range settings.EngineConfineSystemReadPaths {
		rules = append(rules, &landlockRule{path: path, access: rights.readDirectory, optional: true})
	}
	for _, path := range settings.EngineConfineDevicePaths {
		rules = append(rules, &landlockRule{path: path, access: rights.device, optional: true})
	}
	for _, rule := range rules {
		if !filepath.IsAbs(rule.path) {
			unix.Close(ruleset)
			return -1, fmt.Errorf("%w: a rule's path is not absolute", ErrInferEngineUnconfined)
		}
		if err := add(rule.path, rule.access, rule.optional); err != nil {
			unix.Close(ruleset)
			return -1, err
		}
	}
	return ruleset, nil
}

// The ELF interpreter executable names, which the kernel runs it with and so must be executable in the confined image;
// empty for a static executable, or one that does not read as ELF.
func inferEngineElfInterpreter(executable string) string {
	file, err := elf.Open(executable)
	if err != nil {
		return ""
	}
	defer file.Close()
	for _, program := range file.Progs {
		if program.Type != elf.PT_INTERP {
			continue
		}
		data := make([]byte, program.Filesz)
		if _, err := program.ReadAt(data, 0); err != nil {
			return ""
		}
		// the path ends with its NUL
		if i := slices.Index(data, 0); 0 <= i {
			data = data[:i]
		}
		return string(data)
	}
	return ""
}

// The second stage's proof: no_new_privs set, a seccomp filter in place, a socket refused and the denied directory
// unlistable, else the helper is not confined and runs nothing.
func inferEngineConfinedProof(confinement *inferEngineConfinement) error {
	noNewPrivs, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
	if err != nil || noNewPrivs != 1 {
		return fmt.Errorf("%w: no_new_privs is not set", ErrInferEngineUnconfined)
	}
	mode, err := unix.PrctlRetInt(unix.PR_GET_SECCOMP, 0, 0, 0, 0)
	if err != nil || mode != unix.SECCOMP_MODE_FILTER {
		return fmt.Errorf("%w: no seccomp filter is in place", ErrInferEngineUnconfined)
	}
	socket, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err == nil {
		unix.Close(socket)
		return fmt.Errorf("%w: a network socket opened", ErrInferEngineUnconfined)
	}
	if !errors.Is(err, unix.EACCES) {
		return fmt.Errorf("%w: a socket was refused otherwise than by the filter: %s", ErrInferEngineUnconfined, err)
	}
	return inferEngineConfineProbe(confinement.DeniedDirectory)
}
