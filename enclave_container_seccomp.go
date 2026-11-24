//go:build !ios_extension && !sidecar_http

// The containers' seccomp filter (DESIGN-COMPUTE §11.10, D-ENC-13): what answers the kernel attack surface the
// agents' namespaced root opens, beside the runtime's own filter (nspawn's allow list, which already leaves out
// bpf, perf_event_open, the keyrings, kexec and open_by_handle_at). It is a deny list over everything else, so apt,
// services, low ports, gdb and strace keep working:
//
//	nested user namespaces   unshare and clone with CLONE_NEWUSER refused, EPERM; clone3, whose flags sit behind a
//	                         pointer no filter reads, answers ENOSYS, so libc falls back to clone, as Docker's does
//	io_uring                 its three calls answer ENOSYS, so a program falls back to epoll as on a kernel without it
//	BPF and the rest         bpf, userfaultfd, perf_event_open, the keyrings, kexec, module loading and
//	                         open_by_handle_at refused, EPERM, whatever the runtime's list allows
//	foreign ABIs             a call of another architecture's ABI, x32's on amd64 among them, kills the process,
//	                         since the numbers above are the native ABI's; 32-bit programs do not run in a container
//
// The filter is classic BPF over struct seccomp_data, made for one architecture (amd64 or arm64) by
// EnclaveContainerSeccompProgram. The container's first process installs it before it execs the init, and so does every
// Exec's shim before it enters the container (enclave_container_linux.go), so no process in a container runs without
// it. EnclaveSeccompProfile.OciJson is the same profile in OCI's form, for runsc's bundle and for the image, which
// carries it in enclave/container/seccomp.json for review. The numbers here are ABI identifiers, not settings.

package sidecar

import (
	"encoding/json"
	"fmt"

	"golang.org/x/net/bpf"
)

// What a rule answers.
type EnclaveSeccompAction int

const (
	// The call fails with EPERM.
	EnclaveSeccompErrnoPermission EnclaveSeccompAction = iota + 1
	// The call fails with ENOSYS, as on a kernel without it.
	EnclaveSeccompErrnoNoSystem
)

// The seccomp and kernel ABI values the filter is made of (linux/seccomp.h, linux/audit.h, linux/sched.h,
// asm-generic/errno-base.h), the same on amd64 and arm64.
const (
	enclaveSeccompRetKillProcess = uint32(0x80000000)
	enclaveSeccompRetErrno       = uint32(0x00050000)
	enclaveSeccompRetAllow       = uint32(0x7fff0000)
	enclaveSeccompErrnoEperm     = uint32(1)
	enclaveSeccompErrnoEnosys    = uint32(38)
	enclaveSeccompCloneNewUser   = uint32(0x10000000)
	// x32's calls on amd64 carry this bit in their number.
	enclaveSeccompX32SyscallBit  = uint32(0x40000000)
	enclaveSeccompAuditArchAmd64 = uint32(0xc000003e)
	enclaveSeccompAuditArchArm64 = uint32(0xc00000b7)
	// struct seccomp_data: nr at 0, arch at 4, the instruction pointer at 8, args[i] at 16 + 8i, each read by its
	// low 32-bit word, which comes first on both little-endian architectures.
	enclaveSeccompDataNrOffset   = uint32(0)
	enclaveSeccompDataArchOffset = uint32(4)
	enclaveSeccompDataArgsOffset = uint32(16)
	enclaveSeccompDataArgSize    = uint32(8)
	// seccomp's BPF reads 32-bit words alone.
	enclaveSeccompLoadSize = 4
)

// Each architecture's audit value and system call numbers (arch/x86/entry/syscalls/syscall_64.tbl,
// include/uapi/asm-generic/unistd.h), for the calls the profile names.
var enclaveSeccompArchitectures = map[string]*enclaveSeccompArchitecture{
	"amd64": {
		auditArch: enclaveSeccompAuditArchAmd64,
		ociArch:   "SCMP_ARCH_X86_64",
		x32:       true,
		numbers: map[string]uint32{
			"clone": 56, "unshare": 272, "clone3": 435,
			"io_uring_setup": 425, "io_uring_enter": 426, "io_uring_register": 427,
			"bpf": 321, "userfaultfd": 323, "perf_event_open": 298,
			"add_key": 248, "request_key": 249, "keyctl": 250,
			"kexec_load": 246, "kexec_file_load": 320,
			"init_module": 175, "finit_module": 313, "delete_module": 176,
			"open_by_handle_at": 304,
		},
	},
	"arm64": {
		auditArch: enclaveSeccompAuditArchArm64,
		ociArch:   "SCMP_ARCH_AARCH64",
		numbers: map[string]uint32{
			"clone": 220, "unshare": 97, "clone3": 435,
			"io_uring_setup": 425, "io_uring_enter": 426, "io_uring_register": 427,
			"bpf": 280, "userfaultfd": 282, "perf_event_open": 241,
			"add_key": 217, "request_key": 218, "keyctl": 219,
			"kexec_load": 104, "kexec_file_load": 294,
			"init_module": 105, "finit_module": 273, "delete_module": 106,
			"open_by_handle_at": 265,
		},
	},
}

// One architecture's ABI.
type enclaveSeccompArchitecture struct {
	auditArch uint32
	ociArch   string
	// whether x32's calls share the native audit value and must be told apart by their number
	x32     bool
	numbers map[string]uint32
}

// One rule: a call by name and what it answers, when ArgMask is zero always, else only when argument ArgIndex's low
// 32 bits have every bit of ArgMask set.
type EnclaveSeccompRule struct {
	Name     string
	Action   EnclaveSeccompAction
	ArgIndex int
	ArgMask  uint32
}

// The containers' filter, a deny list over the runtime's own.
type EnclaveSeccompProfile struct {
	Rules []*EnclaveSeccompRule
}

// The profile of §11.10's boundary, the same for every container.
func EnclaveContainerSeccompProfile() *EnclaveSeccompProfile {
	rules := []*EnclaveSeccompRule{
		{Name: "unshare", Action: EnclaveSeccompErrnoPermission, ArgIndex: 0, ArgMask: enclaveSeccompCloneNewUser},
		{Name: "clone", Action: EnclaveSeccompErrnoPermission, ArgIndex: 0, ArgMask: enclaveSeccompCloneNewUser},
		{Name: "clone3", Action: EnclaveSeccompErrnoNoSystem},
		{Name: "io_uring_setup", Action: EnclaveSeccompErrnoNoSystem},
		{Name: "io_uring_enter", Action: EnclaveSeccompErrnoNoSystem},
		{Name: "io_uring_register", Action: EnclaveSeccompErrnoNoSystem},
	}
	for _, name := range []string{
		"bpf", "userfaultfd", "perf_event_open", "add_key", "request_key", "keyctl", "kexec_load", "kexec_file_load",
		"init_module", "finit_module", "delete_module", "open_by_handle_at",
	} {
		rules = append(rules, &EnclaveSeccompRule{Name: name, Action: EnclaveSeccompErrnoPermission})
	}
	return &EnclaveSeccompProfile{Rules: rules}
}

// The return value of an action.
func (self EnclaveSeccompAction) ret() (uint32, error) {
	switch self {
	case EnclaveSeccompErrnoPermission:
		return enclaveSeccompRetErrno | enclaveSeccompErrnoEperm, nil
	case EnclaveSeccompErrnoNoSystem:
		return enclaveSeccompRetErrno | enclaveSeccompErrnoEnosys, nil
	}
	return 0, fmt.Errorf("the seccomp action %d", self)
}

// The filter for goarch, amd64 or arm64, as classic BPF over struct seccomp_data: the architecture checked first,
// then each rule's call; anything else allowed. Assemble it to install it; run it on bpf's VM to test it.
func EnclaveContainerSeccompProgram(profile *EnclaveSeccompProfile, goarch string) ([]bpf.Instruction, error) {
	architecture, ok := enclaveSeccompArchitectures[goarch]
	if !ok {
		return nil, fmt.Errorf("no seccomp filter is made for %s", goarch)
	}
	program := []bpf.Instruction{
		bpf.LoadAbsolute{Off: enclaveSeccompDataArchOffset, Size: enclaveSeccompLoadSize},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: architecture.auditArch, SkipTrue: 1},
		bpf.RetConstant{Val: enclaveSeccompRetKillProcess},
		bpf.LoadAbsolute{Off: enclaveSeccompDataNrOffset, Size: enclaveSeccompLoadSize},
	}
	if architecture.x32 {
		program = append(program,
			bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: enclaveSeccompX32SyscallBit, SkipFalse: 1},
			bpf.RetConstant{Val: enclaveSeccompRetKillProcess},
		)
	}
	seen := map[string]bool{}
	for _, rule := range profile.Rules {
		number, ok := architecture.numbers[rule.Name]
		if !ok || seen[rule.Name] {
			return nil, fmt.Errorf("the seccomp rule for %q has no number on %s, or is a second one", rule.Name, goarch)
		}
		seen[rule.Name] = true
		ret, err := rule.Action.ret()
		if err != nil {
			return nil, err
		}
		if rule.ArgMask == 0 {
			// equal: answer; else on to the next rule, A still the number
			program = append(program,
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: number, SkipFalse: 1},
				bpf.RetConstant{Val: ret},
			)
			continue
		}
		if rule.ArgIndex < 0 || 5 < rule.ArgIndex {
			return nil, fmt.Errorf("the seccomp rule for %q reads argument %d", rule.Name, rule.ArgIndex)
		}
		// equal: read the argument and answer either way, since no other rule names this call; else skip the block
		program = append(program,
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: number, SkipFalse: 4},
			bpf.LoadAbsolute{Off: enclaveSeccompDataArgsOffset + enclaveSeccompDataArgSize*uint32(rule.ArgIndex), Size: enclaveSeccompLoadSize},
			bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: rule.ArgMask, SkipFalse: 1},
			bpf.RetConstant{Val: ret},
			bpf.RetConstant{Val: enclaveSeccompRetAllow},
		)
	}
	program = append(program, bpf.RetConstant{Val: enclaveSeccompRetAllow})
	if _, err := bpf.Assemble(program); err != nil {
		return nil, err
	}
	return program, nil
}

// OCI's seccomp form (runtime-spec config-linux.md), for runsc's bundle and the image's copy.
type enclaveSeccompOci struct {
	DefaultAction string                   `json:"defaultAction"`
	Architectures []string                 `json:"architectures"`
	Syscalls      []*enclaveSeccompOciRule `json:"syscalls"`
}

// One OCI rule.
type enclaveSeccompOciRule struct {
	Names    []string                `json:"names"`
	Action   string                  `json:"action"`
	ErrnoRet uint32                  `json:"errnoRet"`
	Args     []*enclaveSeccompOciArg `json:"args,omitempty"`
}

// One OCI argument condition.
type enclaveSeccompOciArg struct {
	Index    int    `json:"index"`
	Value    uint64 `json:"value"`
	ValueTwo uint64 `json:"valueTwo"`
	Op       string `json:"op"`
}

// The profile in OCI's form: the native architectures alone, so a foreign ABI's call fails as the BPF form kills it.
func (self *EnclaveSeccompProfile) oci() (*enclaveSeccompOci, error) {
	architectures := []string{}
	for _, goarch := range []string{"amd64", "arm64"} {
		architectures = append(architectures, enclaveSeccompArchitectures[goarch].ociArch)
	}
	profile := &enclaveSeccompOci{DefaultAction: "SCMP_ACT_ALLOW", Architectures: architectures}
	for _, rule := range self.Rules {
		ret, err := rule.Action.ret()
		if err != nil {
			return nil, err
		}
		ociRule := &enclaveSeccompOciRule{Names: []string{rule.Name}, Action: "SCMP_ACT_ERRNO", ErrnoRet: ret &^ enclaveSeccompRetErrno}
		if rule.ArgMask != 0 {
			ociRule.Args = []*enclaveSeccompOciArg{{
				Index: rule.ArgIndex, Value: uint64(rule.ArgMask), ValueTwo: uint64(rule.ArgMask), Op: "SCMP_CMP_MASKED_EQ",
			}}
		}
		profile.Syscalls = append(profile.Syscalls, ociRule)
	}
	return profile, nil
}

// The profile as OCI's JSON, indented, as the image carries it.
func (self *EnclaveSeccompProfile) OciJson() ([]byte, error) {
	profile, err := self.oci()
	if err != nil {
		return nil, err
	}
	encoded, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}
