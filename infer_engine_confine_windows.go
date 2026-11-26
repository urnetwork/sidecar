//go:build windows && !ios_extension && !sidecar_http

// The helper's confinement on Windows (DESIGN-COMPUTE §6.5; infer_engine_confine.go): the daemon starts the helper in
// an AppContainer with no capabilities, so it has no network, no access to the user's files and no named object of the
// user's session, and grants the container's SID read and execute by ACL on the engine and model directories, inherited
// by what they hold, and on the helper's own executable, which sits in the user's profile. The helper's stdio are the
// only handles it inherits. The helper refuses to run outside an AppContainer, and then proves it cannot list the
// instance's state directory.
//
// One AppContainer profile serves every helper of the user: CreateAppContainerProfile makes it at the first start, and
// DeriveAppContainerSidFromAppContainerName names it after. Granting read again is idempotent, so each start grants it,
// and a directory made since is covered.

package sidecar

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The AppContainer profile every helper runs in.
const (
	inferEngineAppContainerName        = "network.ur.engine"
	inferEngineAppContainerDisplayName = "ur engine"
	inferEngineAppContainerDescription = "ur's local model engine, confined to reading its engine and model files"
)

// Windows' values the start is made of (WinBase.h, WinNT.h, winerror.h), which x/sys does not name: identifiers.
const (
	// PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES
	inferEngineProcThreadAttributeSecurityCapabilities = 0x00020009
	// HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS), which CreateAppContainerProfile answers for a profile made before
	inferEngineHresultAlreadyExists = 0x800700b7
	// TOKEN_INFORMATION_CLASS's TokenIsAppContainer
	inferEngineTokenIsAppContainer = 29
)

// SECURITY_CAPABILITIES (WinNT.h): the container, and no capability.
type inferEngineSecurityCapabilities struct {
	AppContainerSid *windows.SID
	Capabilities    *windows.SIDAndAttributes
	CapabilityCount uint32
	Reserved        uint32
}

// userenv.dll's AppContainer calls, resolved at their first use.
var (
	inferEngineUserenv                       = windows.NewLazySystemDLL("userenv.dll")
	inferEngineCreateAppContainerProfile     = inferEngineUserenv.NewProc("CreateAppContainerProfile")
	inferEngineDeriveAppContainerSidFromName = inferEngineUserenv.NewProc("DeriveAppContainerSidFromAppContainerName")
)

// See infer_engine_confine.go: an AppContainer is made where userenv offers its calls, Windows 8 on.
func inferEngineConfineAvailable() error {
	for _, proc := range []*windows.LazyProc{inferEngineCreateAppContainerProfile, inferEngineDeriveAppContainerSidFromName} {
		if err := proc.Find(); err != nil {
			return fmt.Errorf("%w: this Windows makes no AppContainer (%s), so local inference is unavailable here", ErrInferEngineUnconfined, err)
		}
	}
	return nil
}

// See infer_engine_confine.go: ur-engine.exe beside ur.exe.
func inferEngineDefaultHelperPath(executable string) string {
	return filepath.Join(filepath.Dir(executable), inferEngineHelperName())
}

// The helpers' AppContainer's SID, the profile made at the first call, and what frees it.
func inferEngineAppContainerSid() (*windows.SID, func(), error) {
	if err := inferEngineConfineAvailable(); err != nil {
		return nil, nil, err
	}
	name, err := windows.UTF16PtrFromString(inferEngineAppContainerName)
	if err != nil {
		return nil, nil, err
	}
	display, err := windows.UTF16PtrFromString(inferEngineAppContainerDisplayName)
	if err != nil {
		return nil, nil, err
	}
	description, err := windows.UTF16PtrFromString(inferEngineAppContainerDescription)
	if err != nil {
		return nil, nil, err
	}
	var sid *windows.SID
	result, _, _ := inferEngineCreateAppContainerProfile.Call(uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(display)),
		uintptr(unsafe.Pointer(description)), 0, 0, uintptr(unsafe.Pointer(&sid)))
	if uint32(result) == inferEngineHresultAlreadyExists {
		result, _, _ = inferEngineDeriveAppContainerSidFromName.Call(uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&sid)))
	}
	if uint32(result) != 0 || sid == nil {
		return nil, nil, fmt.Errorf("%w: the AppContainer profile answered 0x%08x", ErrInferEngineUnconfined, uint32(result))
	}
	return sid, func() { windows.FreeSid(sid) }, nil
}

// Grants sid read and execute on path by an ACE in its DACL, inherited by what a directory holds where inherit.
func inferEngineGrantRead(path string, sid *windows.SID, inherit bool) error {
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	inheritance := uint32(windows.NO_INHERITANCE)
	if inherit {
		inheritance = windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_READ | windows.GENERIC_EXECUTE,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       inheritance,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}}, dacl)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}

// env as a Unicode environment block, SYSTEMROOT added from this process's where it names none, as os/exec does, and
// the names sorted as CreateProcess asks.
func inferEngineEnvironmentBlock(env []string) ([]uint16, error) {
	entries := slices.Clone(env)
	if !slices.ContainsFunc(entries, func(entry string) bool { return strings.HasPrefix(strings.ToUpper(entry), "SYSTEMROOT=") }) {
		if root, ok := os.LookupEnv("SYSTEMROOT"); ok {
			entries = append(entries, "SYSTEMROOT="+root)
		}
	}
	sort.SliceStable(entries, func(i int, j int) bool {
		return strings.ToUpper(entries[i]) < strings.ToUpper(entries[j])
	})
	block := []uint16{}
	for _, entry := range entries {
		if strings.ContainsRune(entry, 0) {
			return nil, errors.New("an environment entry holds a NUL")
		}
		encoded, err := windows.UTF16FromString(entry)
		if err != nil {
			return nil, err
		}
		block = append(block, encoded...)
	}
	// an empty block is two NULs; any other ends with one more after its last entry's
	if len(block) == 0 {
		block = append(block, 0)
	}
	return append(block, 0), nil
}

// An inheritable pipe whose child end the helper reads (stdin) or writes (stdout, stderr): the parent's end is not
// inheritable.
func inferEngineChildPipe(childReads bool) (windows.Handle, windows.Handle, error) {
	attributes := &windows.SecurityAttributes{InheritHandle: 1}
	attributes.Length = uint32(unsafe.Sizeof(*attributes))
	var read, write windows.Handle
	if err := windows.CreatePipe(&read, &write, attributes, 0); err != nil {
		return 0, 0, err
	}
	parent, child := read, write
	if childReads {
		parent, child = write, read
	}
	if err := windows.SetHandleInformation(parent, windows.HANDLE_FLAG_INHERIT, 0); err != nil {
		windows.CloseHandle(read)
		windows.CloseHandle(write)
		return 0, 0, err
	}
	return parent, child, nil
}

// See infer_engine_confine.go: the helper in the AppContainer, read granted on the two directories and its executable,
// its stdio the only handles it inherits.
func inferEngineStartChild(spec *inferEngineChildSpec) (*inferEngineChild, error) {
	if err := spec.Confinement.validate(); err != nil {
		return nil, err
	}
	sid, freeSid, err := inferEngineAppContainerSid()
	if err != nil {
		return nil, err
	}
	defer freeSid()
	for _, grant := range []struct {
		path    string
		inherit bool
	}{
		{path: spec.Confinement.EngineDirectory, inherit: true},
		{path: spec.Confinement.ModelDirectory, inherit: true},
		{path: spec.Path, inherit: false},
	} {
		if err := inferEngineGrantRead(grant.path, sid, grant.inherit); err != nil {
			return nil, fmt.Errorf("%w: read could not be granted to the AppContainer: %s", ErrInferEngineUnconfined, err)
		}
	}
	application, err := windows.UTF16PtrFromString(spec.Path)
	if err != nil {
		return nil, err
	}
	commandLine, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(spec.argv()))
	if err != nil {
		return nil, err
	}
	var directory *uint16
	if spec.Directory != "" {
		if directory, err = windows.UTF16PtrFromString(spec.Directory); err != nil {
			return nil, err
		}
	}
	environment, err := inferEngineEnvironmentBlock(spec.environment())
	if err != nil {
		return nil, err
	}

	// the three pipes, each child end inheritable and named in the handle list alone
	ends := []windows.Handle{}
	closeAll := func(handles []windows.Handle) {
		for _, handle := range handles {
			windows.CloseHandle(handle)
		}
	}
	stdinParent, stdinChild, err := inferEngineChildPipe(true)
	if err != nil {
		return nil, err
	}
	ends = append(ends, stdinParent, stdinChild)
	stdoutParent, stdoutChild, err := inferEngineChildPipe(false)
	if err != nil {
		closeAll(ends)
		return nil, err
	}
	ends = append(ends, stdoutParent, stdoutChild)
	stderrParent, stderrChild, err := inferEngineChildPipe(false)
	if err != nil {
		closeAll(ends)
		return nil, err
	}
	ends = append(ends, stderrParent, stderrChild)
	childEnds := []windows.Handle{stdinChild, stdoutChild, stderrChild}

	attributes, err := windows.NewProcThreadAttributeList(2)
	if err != nil {
		closeAll(ends)
		return nil, err
	}
	defer attributes.Delete()
	if err := attributes.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&childEnds[0]),
		uintptr(len(childEnds))*unsafe.Sizeof(childEnds[0])); err != nil {
		closeAll(ends)
		return nil, err
	}
	capabilities := &inferEngineSecurityCapabilities{AppContainerSid: sid}
	if err := attributes.Update(inferEngineProcThreadAttributeSecurityCapabilities, unsafe.Pointer(capabilities),
		unsafe.Sizeof(*capabilities)); err != nil {
		closeAll(ends)
		return nil, err
	}
	startup := &windows.StartupInfoEx{ProcThreadAttributeList: attributes.List()}
	startup.Cb = uint32(unsafe.Sizeof(*startup))
	startup.Flags = windows.STARTF_USESTDHANDLES
	startup.StdInput = stdinChild
	startup.StdOutput = stdoutChild
	startup.StdErr = stderrChild
	information := &windows.ProcessInformation{}
	err = windows.CreateProcess(application, commandLine, nil, nil, true,
		windows.CREATE_UNICODE_ENVIRONMENT|windows.EXTENDED_STARTUPINFO_PRESENT|windows.CREATE_NO_WINDOW,
		&environment[0], directory, &startup.StartupInfo, information)
	runtime.KeepAlive(childEnds)
	runtime.KeepAlive(capabilities)
	runtime.KeepAlive(environment)
	// the child holds its ends now, or there is no child
	closeAll(childEnds)
	if err != nil {
		closeAll([]windows.Handle{stdinParent, stdoutParent, stderrParent})
		return nil, fmt.Errorf("the engine helper does not start in its AppContainer: %w", err)
	}
	windows.CloseHandle(information.Thread)
	process := information.Process

	stderr := os.NewFile(uintptr(stderrParent), "ur-engine stderr")
	go func() {
		defer stderr.Close()
		if spec.Stderr != nil {
			io.Copy(spec.Stderr, stderr)
		} else {
			io.Copy(io.Discard, stderr)
		}
	}()
	var closeOnce sync.Once
	closeProcess := func() {
		closeOnce.Do(func() { windows.CloseHandle(process) })
	}
	var waitLock sync.Mutex
	waited := false
	return &inferEngineChild{
		stdin:  os.NewFile(uintptr(stdinParent), "ur-engine stdin"),
		stdout: os.NewFile(uintptr(stdoutParent), "ur-engine stdout"),
		kill: func() error {
			waitLock.Lock()
			defer waitLock.Unlock()
			if waited {
				return nil
			}
			return windows.TerminateProcess(process, 1)
		},
		wait: func() error {
			if _, err := windows.WaitForSingleObject(process, windows.INFINITE); err != nil {
				return err
			}
			var code uint32
			err := windows.GetExitCodeProcess(process, &code)
			func() {
				waitLock.Lock()
				defer waitLock.Unlock()
				waited = true
			}()
			closeProcess()
			if err != nil {
				return err
			}
			if code != 0 {
				return fmt.Errorf("the engine helper exited with status %d", code)
			}
			return nil
		},
	}, nil
}

// See infer_engine_confine.go: the daemon started this process in its AppContainer, which holds already, so this only
// checks the token is one and proves the state directory unlistable.
func inferEngineConfine(confinement *inferEngineConfinement, settings *InferSettings, argv []string, env []string) error {
	if err := confinement.validate(); err != nil {
		return err
	}
	var isAppContainer uint32
	var returned uint32
	err := windows.GetTokenInformation(windows.GetCurrentProcessToken(), inferEngineTokenIsAppContainer,
		(*byte)(unsafe.Pointer(&isAppContainer)), uint32(unsafe.Sizeof(isAppContainer)), &returned)
	if err != nil || isAppContainer == 0 {
		return fmt.Errorf("%w: the helper does not run in an AppContainer", ErrInferEngineUnconfined)
	}
	return inferEngineConfineProbe(confinement.DeniedDirectory)
}
